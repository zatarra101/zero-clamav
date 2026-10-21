#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path

import boto3
from botocore.config import Config

MAX_BYTES = 10 * 1024 * 1024
QUARANTINE_ROOT = "helpdesk/poc-quarantine/"
SAFE_ROOT = "helpdesk/poc-safe/"
KEY_RE = re.compile(r"^helpdesk/poc-quarantine/[0-9a-f-]{36}/[A-Za-z0-9._-]+$")


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def callback(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        required("CALLBACK_URL"),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Scanner-Secret": required("CALLBACK_SECRET"),
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"Callback returned HTTP {response.status}")


endpoint = required("R2_ENDPOINT")
access_key = required("R2_ACCESS_KEY_ID")
secret_key = required("R2_SECRET_ACCESS_KEY")
bucket = required("R2_BUCKET")
attachment_id = required("ATTACHMENT_ID")
storage_key = required("STORAGE_KEY")
expected = required("EXPECTED_RESULT")

if not KEY_RE.fullmatch(storage_key):
    raise SystemExit(f"Refusing storage key outside POC quarantine contract: {storage_key}")
if expected not in {"clean", "infected"}:
    raise SystemExit("EXPECTED_RESULT must be clean or infected")

s3 = boto3.client(
    "s3",
    endpoint_url=endpoint,
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name="auto",
    config=Config(signature_version="s3v4"),
)


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


def scan() -> None:
    meta = head(storage_key)
    size = int(meta.get("ContentLength", 0))
    if size > MAX_BYTES:
        raise RuntimeError(f"Object exceeds scanner limit: {size} bytes")

    with tempfile.TemporaryDirectory(prefix="zero-clamav-dispatch-") as temp:
        path = Path(temp) / Path(storage_key).name
        with path.open("wb") as output:
            s3.download_fileobj(bucket, storage_key, output)

        digest = sha256_file(path)
        result = subprocess.run(
            ["clamscan", "--no-summary", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            actual = "clean"
        elif result.returncode == 1:
            actual = "infected"
        else:
            raise RuntimeError(f"ClamAV error exit={result.returncode}")

        if actual != expected:
            raise RuntimeError(f"Expected {expected}, got {actual}")

        safe_key = None
        if actual == "clean":
            safe_key = f"{SAFE_ROOT}{attachment_id}/{Path(storage_key).name}"
            with path.open("rb") as source:
                s3.upload_fileobj(source, bucket, safe_key)
            safe_meta = head(safe_key)
            if int(safe_meta.get("ContentLength", -1)) != size:
                raise RuntimeError("Safe copy size verification failed")

        delete(storage_key)

        payload = {
            "attachment_id": attachment_id,
            "storage_key": storage_key,
            "scan_result": actual,
            "scanner": "zero-clamav",
            "scanner_version": "poc-1",
            "sha256": digest,
        }
        if safe_key:
            payload["safe_storage_key"] = safe_key

        callback(payload)
        print(f"CALLBACK_POC_RESULT=PASS result={actual} size={size}")


scan()
