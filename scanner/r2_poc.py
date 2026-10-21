#!/usr/bin/env python3
import hashlib
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import boto3
from botocore.config import Config

MAX_BYTES = 10 * 1024 * 1024
QUARANTINE_ROOT = "helpdesk/poc-quarantine/"
SAFE_ROOT = "helpdesk/poc-safe/"


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


endpoint = required("R2_ENDPOINT")
access_key = required("R2_ACCESS_KEY_ID")
secret_key = required("R2_SECRET_ACCESS_KEY")
bucket = required("R2_BUCKET")

s3 = boto3.client(
    "s3",
    endpoint_url=endpoint,
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name="auto",
    config=Config(signature_version="s3v4"),
)

run_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:12]}"
quarantine_prefix = f"{QUARANTINE_ROOT}{run_id}/"
safe_prefix = f"{SAFE_ROOT}{run_id}/"


def put(key: str, data: bytes) -> None:
    s3.put_object(Bucket=bucket, Key=key, Body=data)


def head(key: str):
    return s3.head_object(Bucket=bucket, Key=key)


def delete(key: str) -> None:
    s3.delete_object(Bucket=bucket, Key=key)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_key(key: str, expected: str) -> None:
    if not key.startswith(QUARANTINE_ROOT):
        raise RuntimeError(f"Refusing key outside POC quarantine prefix: {key}")

    meta = head(key)
    size = int(meta.get("ContentLength", 0))
    if size > MAX_BYTES:
        raise RuntimeError(f"Object exceeds scanner limit: {size} bytes")

    with tempfile.TemporaryDirectory(prefix="zero-clamav-") as temp:
        path = Path(temp) / Path(key).name
        with path.open("wb") as output:
            s3.download_fileobj(bucket, key, output)

        digest = sha256_file(path)
        result = subprocess.run(
            ["clamscan", "--no-summary", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

        if expected == "clean":
            if result.returncode != 0:
                raise RuntimeError(
                    f"Expected clean object, ClamAV exit={result.returncode}: "
                    f"{result.stdout.strip()} {result.stderr.strip()}"
                )

            safe_key = f"{safe_prefix}{Path(key).name}"
            with path.open("rb") as source:
                s3.upload_fileobj(source, bucket, safe_key)
            safe_meta = head(safe_key)
            if int(safe_meta.get("ContentLength", -1)) != size:
                raise RuntimeError("Safe copy size verification failed")
            delete(key)
            print(f"PASS clean: size={size} sha256={digest} moved_to_safe=true")
        elif expected == "infected":
            if result.returncode != 1:
                raise RuntimeError(
                    f"Expected infection detection, ClamAV exit={result.returncode}: "
                    f"{result.stdout.strip()} {result.stderr.strip()}"
                )
            delete(key)
            print(f"PASS infected: size={size} sha256={digest} quarantine_deleted=true")
        else:
            raise RuntimeError(f"Unknown expected result: {expected}")


# The EICAR test string is constructed from pieces so the canonical signature is
# never stored verbatim as a repository file.
eicar = "X5O!P%@AP[4" + "\\" + "PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

clean_key = f"{quarantine_prefix}clean.pdf"
eicar_key = f"{quarantine_prefix}eicar.com"

put(clean_key, b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
put(eicar_key, eicar.encode("ascii"))

print(f"POC_RUN_ID={run_id}")
print("Testing R2 quarantine -> ClamAV -> safe/reject path")
scan_key(clean_key, "clean")
scan_key(eicar_key, "infected")

print("R2_CLAMAV_POC_RESULT=PASS")
