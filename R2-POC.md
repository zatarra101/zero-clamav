# R2 ClamAV Integration POC

This is the second-stage disposable POC. It remains isolated from `zatarra101/edtech-platform`.

## Flow tested

`GitHub public runner -> Docker/ClamAV -> R2 quarantine -> download -> scan -> clean to R2 safe / infected deletion`

The POC uses only the dedicated prefixes:

- `helpdesk/poc-quarantine/<run-id>/`
- `helpdesk/poc-safe/<run-id>/`

It creates a synthetic PDF and a runtime-generated EICAR test object. It does not read arbitrary production objects.

## Required GitHub repository secrets

Add these four repository secrets under **Settings -> Secrets and variables -> Actions**:

- `R2_ENDPOINT` — Cloudflare R2 S3-compatible endpoint.
- `R2_ACCESS_KEY_ID` — a dedicated R2 access key.
- `R2_SECRET_ACCESS_KEY` — the matching secret.
- `R2_BUCKET` — the bucket used for this POC.

Use a dedicated R2 token with the minimum permissions needed for the POC bucket/prefix. Do not commit credentials to this repository.

## Run

1. Open **Actions**.
2. Select **R2 ClamAV Integration POC**.
3. Choose **Run workflow**.
4. Verify `R2_CLAMAV_POC_RESULT=PASS`.

## What success proves

- GitHub runner can reach R2.
- R2 quarantine objects can be downloaded by the scanner.
- ClamAV scans the downloaded object.
- A clean object is copied into the POC safe prefix and the quarantine copy is deleted.
- EICAR is detected and its quarantine object is deleted.
- No production Help Desk attachment or Supabase callback is touched by this POC.

## Next stage after this passes

Add an externally-triggered `repository_dispatch` scan request and a callback contract. GitHub supports `repository_dispatch` for activity originating outside GitHub, with a `client_payload` delivered to the workflow. A fine-grained token used to dispatch the event requires repository Contents write permission. Keep that token outside this public repository.
