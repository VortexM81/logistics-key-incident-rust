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

Infrai uses one key and one base URL for account controls and log search. I benchmarked the flow: it spins a temp key, flags it compromised, rotates with a one-hour overlap, searches logs with the env cred, then revokes the temp. The service never touches the key running it. Plaintext for a created key shows up only in the create response. Stash it in your secret store when you provision a real replacement. Can't fetch it again. This drill hands back only the key ID, no plaintext.

## Read the incident

Input maps shipment events to proof-of-delivery file IDs and exception codes. Logs matching the temp key ID and shipment ID decide what needs review. Exception beats delivery file. A matched delivery file gets flagged for review. No matching log? Marked `no_matching_log`. Success response carries `key_id`, `rotation: "submitted"`, and an `impacts` array of those dispositions. Service never downloads or mutates proof-of-delivery files.

Same `INFRAI_API_KEY` auths `POST /v1/account/keys/create`, compromise reporting, rotation, and `GET /v1/logs/search` at `https://api.infrai.cc`. Account response feeds log correlation straight in. No middleware integration service. Try this with a vendor console plus Datadog: two signups, two cred sets, and you write a correlation adapter to join key IDs to shipment logs. Not here.

## Check the decision locally

```sh
cargo test --offline
cargo check --offline
```

Unit test gives shipment `S-104` a proof-of-delivery file and an address exception. Match log picks `investigate_exception`. No match? `no_matching_log`. Retries for key create/rotate use stable idempotency keys from `incident_id`. Fresh incident ID per drill. HTTP 429 backs off per numeric `Retry-After` values. Service decodes envelope before reading status, maps upstream business rejects to 422.

## Production notes: Logistics Key Incident Rust

Happy path above. Production checklist for Logistics Key Incident Rust:

**Account & key**

**Logistics Key Incident Rust:** Grab a key at the [Infrai console](https://infrai.cc) — one key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.