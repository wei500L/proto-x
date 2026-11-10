import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from packaging_check import inspect, markdown_targets


class PackagingCheckTests(unittest.TestCase):
    def repo(self, root):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture"], check=True)
        (root / ".gitignore").write_text(".local/\n")

    def test_compressed_secret_and_path_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo(root)
            secret = "fixture" + "-private-value"
            with tarfile.open(root / "source.tar.gz", "w:gz") as tar:
                payload = ("token=" + secret).encode()
                entry = tarfile.TarInfo(secret + ".txt")
                entry.size = len(payload)
                tar.addfile(entry, io.BytesIO(payload))
            result = inspect(root, [("test_credential", secret.encode())], root / "report.json", "final")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["archive_regular_files_checked"], 1)
            self.assertEqual(result["public_files_checked"], 2)
            self.assertNotIn(secret, json.dumps(result))
            self.assertEqual(result["findings"][0]["occurrences"], 2)

    def test_archive_traversal_and_links_never_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo(root)
            with tarfile.open(root / "unsafe.tar", "w") as tar:
                entry = tarfile.TarInfo("../escaped")
                entry.size = 4
                tar.addfile(entry, io.BytesIO(b"test"))
                entry = tarfile.TarInfo("symbolic")
                entry.type, entry.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tar.addfile(entry)
            result = inspect(root, [], root / "report.json", "final")
            self.assertEqual({f["category"] for f in result["findings"]}, {"unsafe_archive_member_path", "unsafe_archive_link"})
            self.assertEqual(result["archive_regular_files_checked"], 0)
            self.assertFalse((root / "symbolic").exists())

    def test_links_ignore_code_and_external_but_find_missing_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo(root)
            (root / ".local").mkdir()
            (root / ".local" / "secret.txt").write_text("privatefixture")
            (root / "actual file.txt").write_text("publicfixture")
            (root / "README.md").write_text('''[valid](actual%20file.txt#section)
[remote](https://example.invalid/nope)
`[code](not-real.txt)`
```md
[code](not-real.txt)
```
[missing](absent.txt)
[private](.local/secret.txt)
[named]: actual%20file.txt
''')
            result = inspect(root, [("ignored_value", b"privatefixture")], root / "report.json", "preliminary")
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["local_link_targets_checked"], 4)
            self.assertEqual({f["category"] for f in result["link_findings"]}, {"missing_local_target", "nonpublic_local_target"})
            self.assertTrue(all(f["changed_file"] for f in result["link_findings"]))

    def test_clean_preliminary_is_never_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo(root)
            result = inspect(root, [], root / "report.json", "preliminary")
            self.assertEqual(result["status"], "preliminary_passed")
            result = inspect(root, [], root / "report.json", "final")
            self.assertEqual(result["status"], "passed")

    def test_encoded_private_key_pattern_reports_category_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo(root)
            key = "A" * 43 + "="
            (root / "mistaken-config.json").write_text(json.dumps({"private_key": key}))
            result = inspect(root, [], root / "report.json", "final")
            self.assertEqual(result["findings"][0]["category"], "encoded_private_key_json")
            self.assertNotIn(key, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
