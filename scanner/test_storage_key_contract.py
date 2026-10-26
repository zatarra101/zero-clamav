import unittest

from scanner.storage_key_contract import validate_storage_key


ATTACHMENT = "6876c442-b427-4907-95b9-1e0618c8a3c5"
UPLOADER = "1c6ac29c-9998-496a-84b1-dbf168ef01c8"
RANDOM_FILENAME = "13e59b5e-e61e-470f-82c3-107e961bf9b8.jpg"


class StorageKeyContractTests(unittest.TestCase):
    def test_student_uuid_filename_is_not_misclassified_as_user_scoped(self):
        key = f"helpdesk/quarantine/{ATTACHMENT}/{RANDOM_FILENAME}"
        self.assertEqual(validate_storage_key(ATTACHMENT, key), "student")

    def test_student_non_uuid_filename(self):
        key = f"helpdesk/quarantine/{ATTACHMENT}/lecture.png"
        self.assertEqual(validate_storage_key(ATTACHMENT, key), "student")

    def test_actual_pending_student_attachment_from_supabase(self):
        attachment_id = "bc53ddf5-c0ea-42cb-85d6-627fc51fbf3a"
        key = (
            "helpdesk/quarantine/bc53ddf5-c0ea-42cb-85d6-627fc51fbf3a/"
            "144bf826-9121-4b33-aecd-5e17cb2dcbe8.jpg"
        )
        self.assertEqual(validate_storage_key(attachment_id, key), "student")

    def test_actual_failed_admin_attachment_from_github_run(self):
        attachment_id = "a39eb38f-5ea0-4f4f-b07e-5af092207400"
        key = (
            "helpdesk/quarantine/1c6ac29c-9998-496a-84b1-dbf168ef01c8/"
            "a39eb38f-5ea0-4f4f-b07e-5af092207400.pdf"
        )
        self.assertEqual(
            validate_storage_key(attachment_id, key),
            "legacy_user_scoped",
        )

    def test_legacy_admin_upload(self):
        key = f"helpdesk/quarantine/{UPLOADER}/{ATTACHMENT}.pdf"
        self.assertEqual(validate_storage_key(ATTACHMENT, key), "legacy_user_scoped")

    def test_current_staff_upload(self):
        key = f"helpdesk/quarantine/staff/{UPLOADER}/{ATTACHMENT}.pdf"
        self.assertEqual(validate_storage_key(ATTACHMENT, key), "staff")

    def test_wrong_student_folder_is_rejected(self):
        key = f"helpdesk/quarantine/{UPLOADER}/other-file.jpg"
        with self.assertRaisesRegex(ValueError, "Invalid production quarantine storage_key"):
            validate_storage_key(ATTACHMENT, key)

    def test_wrong_legacy_attachment_filename_is_rejected(self):
        other_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        key = f"helpdesk/quarantine/{UPLOADER}/{other_id}.pdf"
        with self.assertRaisesRegex(ValueError, "user-scoped storage_key"):
            validate_storage_key(ATTACHMENT, key)

    def test_path_outside_quarantine_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid production quarantine storage_key"):
            validate_storage_key(ATTACHMENT, f"helpdesk/safe/{ATTACHMENT}/file.pdf")

    def test_malformed_attachment_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ATTACHMENT_ID must be a UUID"):
            validate_storage_key("not-a-uuid", "helpdesk/quarantine/not-a-uuid/file.pdf")


if __name__ == "__main__":
    unittest.main()
