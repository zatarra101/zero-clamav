# zero-clamav

A separate proof-of-concept repository for testing a **₹0 incremental-cost ClamAV scanner runtime** using public GitHub Actions runners.

This repository is intentionally separate from the EdTech application repository. It does **not** modify or merge into `zatarra101/edtech-platform`.

## What this POC proves

The current test proves only the core scanner runtime:

`GitHub-hosted runner → Docker → ClamAV → clean-file decision + EICAR detection`

The workflow is manual and uses synthetic test data. No R2 or Supabase connection is present yet.

## Run the POC

1. Open **Actions**.
2. Select **Zero ClamAV POC**.
3. Choose **Run workflow**.
4. Wait for the Docker build and ClamAV tests to finish.

A successful run ends with:

`CLAMAV_POC_RESULT=PASS`

## Tests

- Synthetic PDF: expected clean.
- Synthetic PNG: expected clean.
- Synthetic JPEG: expected clean.
- EICAR test string: expected infected/detected.

The EICAR string is generated at runtime and is not committed to the repository.

## Current boundary

This is **not production yet**. It does not access:

- Cloudflare R2
- Supabase
- student files
- teacher/admin files
- production secrets
- production callbacks

Only after this isolated POC passes should the next stage be designed: secure quarantine-object dispatch, ClamAV scanning, idempotent result handling, and Supabase/R2 integration.

## Cost goal

The scanner experiment is being designed around the requirement of **no scanner payment**. No paid Cloud Run, Cloudflare Containers, AWS, Azure, or other paid scanner runtime is used by this POC.
