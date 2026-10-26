#!/usr/bin/env python3
"""Single source of truth for validating Help Desk quarantine object keys."""

import re
import sys

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def validate_storage_key(attachment_id: str, storage_key: str) -> str:
    """Return the matching contract name or raise ValueError.

    Current student uploads use:
      helpdesk/quarantine/<attachment-id>/<random-file-name>.<ext>

    Older user-scoped staff/admin uploads use:
      helpdesk/quarantine/<uploader-id>/<attachment-id>.<ext>

    Current staff uploads use:
      helpdesk/quarantine/staff/<uploader-id>/<attachment-id>.<ext>

    A student filename may itself be a UUID. Classify by the relationship to
    attachment_id, not by the overlapping UUID/UUID filename shape.
    """
    if not re.fullmatch(UUID, attachment_id):
        raise ValueError("ATTACHMENT_ID must be a UUID")

    student = re.fullmatch(
        rf"helpdesk/quarantine/({UUID})/([A-Za-z0-9._-]+)",
        storage_key,
    )
    if student and student.group(1) == attachment_id:
        return "student"

    staff = re.fullmatch(
        rf"helpdesk/quarantine/staff/({UUID})/({UUID})\.([A-Za-z0-9]+)",
        storage_key,
    )
    if staff:
        if staff.group(2) == attachment_id:
            return "staff"
        raise ValueError("staff storage_key does not belong to attachment_id")

    legacy_user_scoped = re.fullmatch(
        rf"helpdesk/quarantine/({UUID})/({UUID})\.([A-Za-z0-9]+)",
        storage_key,
    )
    if legacy_user_scoped:
        if legacy_user_scoped.group(2) == attachment_id:
            return "legacy_user_scoped"
        raise ValueError("user-scoped storage_key does not belong to attachment_id")

    raise ValueError("Invalid production quarantine storage_key")


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: storage_key_contract.py ATTACHMENT_ID STORAGE_KEY", file=sys.stderr)
        return 2
    try:
        kind = validate_storage_key(sys.argv[1], sys.argv[2])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Quarantine storage-key contract validated: {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
