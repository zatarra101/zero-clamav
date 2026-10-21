#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import boto3
from botocore.config import Config

MAX_BYTES = 10 * 1024 * 1024
QUARANTINE_ROOT = "helpdesk/quarantine/"
SAFE_ROOT = "helpdesk/safe/"
KEY_RE = re.compile(r"^helpdesk/quarantine/[0-9a-f-]{36}/[A-Za-z0-9._-]+$")


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


endpoint = required("R2_ENDPOINT")
access_key = required("R2_ACCESS_KEY_ID")
secret_key = required("R2_SECRET_ACCESS_KEY")
bucket = required("R2_BUCKET")
attachment_id = required("ATTACHMENT_ID")
storage_key = required("STORAGE_KEY")
callback_url = required("CALLBACK_URL")
callback_secret = required("CALLBACK_SECRET")

if not re.fullmatch(r"[0-9a-f-]{36}", attachment_id):
    raise SystemExit("ATTACHMENT_ID must be a UUID")
if not KEY_RE.fullmatch(storage_key):
    raise SystemExit(f"Refusing storage key outside production quarantine contract: {storage_key}")
if not storage_key.startswith(f"{QUARANTINE_ROOT}{attachment_id}/"):
    raise SystemExit("STORAGE_KEY attachment path does not match ATTACHMENT_ID")

s3 = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="auto", config=Config(signature_version="s3v4"))


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


def send_callback(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(callback_url, data=body, method="POST", headers={"Content-Type": "application/json", "x-helpdesk-scan-secret": callback_secret})
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"Callback returned HTTP {response.status}")


def scan() -> None:
    meta = head(storage_key)
    size = int(meta.get("ContentLength", 0))
    if size <= 0:
        raise RuntimeError("Quarantine object is empty")
    if size > MAX_BYTES:
        raise RuntimeError(f"Object exceeds scanner limit: {size} bytes")

    with tempfile.TemporaryDirectory(prefix="zero-clamav-production-") as temp:
        path = Path(temp) / Path(storage_key).name
        with path.open("wb") as output:
            s3.download_fileobj(bucket, storage_key, output)
        digest = sha256_file(path)
        result = subprocess.run(["clamscan", "--no-summary", str(path)], check=False, capture_output=True, text=True)
        if result.returncode == 0:
            scan_result = "clean"
        elif result.returncode == 1:
            scan_result = "infected"
        else:
            raise RuntimeError(f"ClamAV error exit={result.returncode}: {result.stderr.strip()}")

        safe_key = None
        if scan_result == "clean":
            safe_key = f"{SAFE_ROOT}{attachment_id}/{Path(storage_key).name}"
            with path.open("rb") as source:
                s3.upload_fileobj(source, bucket, safe_key)
            if int(head(safe_key).get("ContentLength", -1)) != size:
                raise RuntimeError("Safe copy size verification failed")

        delete(storage_key)
        send_callback({"attachment_id": attachment_id, "previous_storage_key": storage_key, "safe_storage_key": safe_key, "scan_result": scan_result, "scanner": "zero-clamav", "scanner_version": "production-contract-1", "scan_error": None, "sha256": digest})
        print(f"PRODUCTION_CONTRACT_RESULT=PASS result={scan_result} size={size} sha256={digest}")


scan()
