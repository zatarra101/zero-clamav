# Security boundaries for the POC

This repository is a disposable proof of concept for validating a zero-cost ClamAV runtime on a public GitHub Actions runner.

## Current scope

- Synthetic local test files only.
- ClamAV runs inside an isolated Docker image.
- The workflow is manual (`workflow_dispatch`) only.
- GitHub Actions permissions are limited to `contents: read`.
- No R2 credentials.
- No Supabase credentials.
- No student, teacher, admin, or production files.
- No production callback endpoint.

## Important

Do not add production credentials, storage tokens, JWTs, scanner secrets, or real user files to this repository or its workflow until a separate production design is reviewed and explicitly approved.

The EICAR test string is generated at runtime and is not stored as a repository file.
