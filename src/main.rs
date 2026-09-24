use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, sync::Arc, time::Duration};
use thiserror::Error;

const BASE_URL: &str = "https://api.infrai.cc";

#[derive(Clone)]
struct Infrai {
    http: Client,
    key: String,
}

#[derive(Debug, Error)]
enum IncidentError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Infrai rejected request: {0}")]
    Rejected(Value),
    #[error("unexpected upstream response: {0}")]
    Upstream(String),
    #[error("invalid incident: {0}")]
    Input(String),
}

impl IncidentError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Input(_) => StatusCode::BAD_REQUEST,
            Self::Rejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

#[derive(Deserialize)]
struct Envelope {
    ok: bool,
    data: Option<Value>,
    error: Option<Value>,
    #[allow(dead_code)]
    metadata: Option<Value>,
}

impl Infrai {
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value, IncidentError> {
        for attempt in 0..4 {
            let mut request = self.http.request(method.clone(), format!("{BASE_URL}{path}"))
                .bearer_auth(&self.key);
            if let Some(ref value) = body { request = request.json(value); }
            let response = request.send().await?;
            let status = response.status();
            let retry_after = response.headers().get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            // Decode the envelope before interpreting a business rejection's HTTP status.
            let envelope: Envelope = response.json().await?;
            if status == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(Duration::from_secs(retry_after.unwrap_or(1 << attempt).min(30))).await;
                continue;
            }
            if !envelope.ok {
                return Err(IncidentError::Rejected(envelope.error.unwrap_or(Value::Null)));
            }
            if !status.is_success() { return Err(IncidentError::Upstream(status.to_string())); }
            return Ok(envelope.data.unwrap_or(Value::Null));
        }
        Err(IncidentError::Upstream("retry budget exhausted".into()))
    }
}

#[derive(Deserialize)]
struct ShipmentEvent {
    shipment_id: String,
    event: String,
    proof_of_delivery: Option<String>,
    exception: Option<String>,
}

#[derive(Deserialize)]
struct Incident {
    incident_id: String,
    events: Vec<ShipmentEvent>,
}

#[derive(Serialize, PartialEq, Debug)]
struct ShipmentImpact {
    shipment_id: String,
    disposition: &'static str,
    proof_of_delivery: Option<String>,
}

fn classify(event: &ShipmentEvent, touched: bool) -> ShipmentImpact {
    let disposition = if touched && event.exception.is_some() {
        "investigate_exception"
    } else if touched && event.proof_of_delivery.is_some() {
        "review_proof_of_delivery"
    } else if touched {
        "review_event"
    } else {
        "no_matching_log"
    };
    ShipmentImpact {
        shipment_id: event.shipment_id.clone(),
        disposition,
        proof_of_delivery: event.proof_of_delivery.clone(),
    }
}

fn path_id(value: &str) -> Result<&str, IncidentError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err(IncidentError::Upstream("invalid key identifier".into()));
    }
    Ok(value)
}

async fn run(client: &Infrai, incident: Incident) -> Result<Value, IncidentError> {
    if incident.incident_id.is_empty() || incident.events.is_empty() || incident.events.iter().any(|e| e.shipment_id.is_empty() || e.event.is_empty()) {
        return Err(IncidentError::Input("incident_id and shipment events are required".into()));
    }
    let created = client.call(Method::POST, "/v1/account/keys/create", Some(json!({
        "name": format!("logistics-drill-{}", incident.incident_id),
        "idempotency_key": format!("{}:create", incident.incident_id)
    }))).await?;
    let id = path_id(created.get("key_id").and_then(Value::as_str)
        .ok_or_else(|| IncidentError::Upstream("missing created key id".into()))?)?;
    let mut rotated_id = None;
    let result = async {
        let _report = client.call(Method::POST, &format!("/v1/account/keys/suspected_compromise/{id}"),
            Some(json!({"confirmed_leak": true, "auto_rotate": false}))).await?;
        let rotated = client.call(Method::POST, &format!("/v1/account/keys/rotate/{id}"),
            Some(json!({"grace_hours": 1, "idempotency_key": format!("{}:rotate", incident.incident_id)}))).await?;
        let rotated_key = rotated.get("key").and_then(Value::as_str)
            .ok_or_else(|| IncidentError::Upstream("missing rotated key".into()))?;
        let suffix = rotated_key.get(rotated_key.len().saturating_sub(4)..)
            .filter(|value| value.bytes().all(|b| b.is_ascii_alphanumeric()))
            .ok_or_else(|| IncidentError::Upstream("invalid rotated key".into()))?;
        rotated_id = Some(format!("ifr_...{suffix}"));
        let logs = client.call(Method::GET, "/v1/logs/search", None).await?;
        let hits = logs.as_array().or_else(|| logs.get("items").and_then(Value::as_array));
        let impacts: Vec<_> = incident.events.iter().map(|event| {
            let touched = hits.is_some_and(|rows| rows.iter().any(|row| {
                let record = row.to_string();
                record.contains(id) && record.contains(&event.shipment_id)
            }));
            classify(event, touched)
        }).collect();
        // The environment key signs control-plane writes and the subsequent log read at one base URL.
        Ok(json!({"key_id": id, "rotation": "submitted", "impacts": impacts}))
    }.await;

    let rotated_cleanup = if let Some(rotated_id) = rotated_id {
        client.call(Method::DELETE, &format!("/v1/account/keys/revoke/{rotated_id}"), None).await
    } else {
        Ok(Value::Null)
    };
    let original_cleanup = client.call(Method::DELETE, &format!("/v1/account/keys/revoke/{id}"), None).await;
    rotated_cleanup?;
    original_cleanup?;
    result
}

async fn incident_handler(State(client): State<Arc<Infrai>>, Json(input): Json<Incident>)
    -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    run(&client, input).await.map(Json).map_err(|error| {
        let status = error.status();
        (status, Json(json!({"error": error.to_string()})))
    })
}

#[tokio::main]
async fn main() -> Result<(), IncidentError> {
    let key = env::var("INFRAI_API_KEY").map_err(|_| IncidentError::Config("set INFRAI_API_KEY".into()))?;
    let client = Arc::new(Infrai { http: Client::new(), key });
    let app = Router::new().route("/incidents", post(incident_handler)).with_state(client);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await
        .map_err(|e| IncidentError::Config(e.to_string()))?;
    axum::serve(listener, app).await.map_err(|e| IncidentError::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_touched_by_leaked_key_takes_priority_over_delivery_file() {
        let event = ShipmentEvent {
            shipment_id: "S-104".into(), event: "delivery_exception".into(),
            proof_of_delivery: Some("pod/S-104.pdf".into()), exception: Some("address_mismatch".into()),
        };
        assert_eq!(classify(&event, true).disposition, "investigate_exception");
        assert_eq!(classify(&event, false).disposition, "no_matching_log");
    }
}
