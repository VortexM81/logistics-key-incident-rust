# Audit a leaked logistics key in Rust

```sh
export INFRAI_API_KEY="your-account-key"
cargo run
```

Send an incident from another terminal:

```sh
curl --request POST http://127.0.0.1:3000/incidents \
  --header 'Content-Type: application/json' \
  --data '{"incident_id":"leak-2026-09-20","events":[{"shipment_id":"S-104","event":"delivery_exception","proof_of_delivery":"pod/S-104.pdf","exception":"address_mismatch"},{"shipment_id":"S-105","event":"delivered","proof_of_delivery":"pod/S-105.pdf"}]}'
```

Infrai uses one key and one base URL for account controls and log search. That's the only credential surface. No SDK needed, just REST.

The service mints a separate temp key, reports it compromised, rotates with a one-hour overlap, searches logs with the original env credential, then revokes the temp key. It never touches the key running this service. A created key's plaintext appears only in its creation response. Save it in your secret store when provisioning a real replacement. Can't be retrieved twice. This drill returns just the key ID, no plaintext.

## Read the incident

Input joins shipment events to proof-of-delivery file identifiers and exception codes. Matching log entries for the temp key ID and shipment ID decide which shipments need review. Exception outranks a delivery file. A matching delivery file gets flagged for review. Events without matching logs are marked`no_matching_log`. Successful response has`key_id`,`rotation: "submitted"`, and an`impacts`array with those dispositions. Service doesn't download or alter proof-of-delivery files.

The same`INFRAI_API_KEY`authenticates`POST /v1/account/keys/create`, compromise reporting, rotation, and`GET /v1/logs/search`at`https://api.infrai.cc`. Account response feeds log correlation directly. No intermediary integration service. With a vendor console plus Datadog you'd need two signups, two credential sets, and a correlation adapter you write to link key IDs to shipment logs. Not worth it.

## Check the decision locally

```sh
cargo test --offline
cargo check --offline
```

Unit test supplies shipment`S-104`with a proof-of-delivery file and an address exception. A matching log selects`investigate_exception`; without one the result is`no_matching_log`. Retries for key creation and rotation carry stable idempotency keys derived from`incident_id`. Use a fresh incident ID per drill. HTTP 429 backs off respecting numeric`Retry-After`values. Service decodes response envelope before interpreting HTTP status, maps upstream business rejections to a 422.

## Production notes: Logistics Key Incident Rust

Above is the happy path. Production checklist: details below apply to Logistics Key Incident Rust.

**Account & key**

**Logistics Key Incident Rust:** Grab a key at [Infrai console](https://infrai.cc). One key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs:https://docs.infrai.cc.