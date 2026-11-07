#!/usr/bin/env python3
"""Local deployment transaction checks; never contacts a host or runs systemd.

The real deployment shell, packager, tar, checksums and file operations run in a
temporary .local tree. SSH, ownership/account operations and systemd are fakes.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
ASSETS = "protox server.json server.crt server.key token cover ech-keys.json ech-config.bin ca.crt ca.pem protox.service package.sha256".split()


def mock_tool(tool, args):
    sandbox = Path(os.environ["DEPLOY_CHECK_ROOT"])
    base = sandbox / "opt/proto-x"
    unit = sandbox / "etc/systemd/system/protox.service"
    control = sandbox / "control"
    with (control / "calls.jsonl").open("a") as log:
        log.write(json.dumps([tool] + args) + "\n")

    def mapped(value):
        return value.replace("/opt/proto-x", str(base)).replace("/etc/systemd/system", str(unit.parent))

    def ssh_args(values):
        while values and values[0] in ("-F", "-o"):
            values = values[2:]
        return values

    if tool == "ssh":
        values = ssh_args(args)
        if not values or values[0] != "protox-test":
            return 91
        command = " ".join(values[1:])
        data = sys.stdin.buffer.read() if command.startswith("sh -s") else b""
        result = subprocess.run(["sh", "-c", mapped(command)], input=mapped(data.decode()).encode(), capture_output=True)
        sys.stdout.buffer.write(result.stdout.replace(str(base).encode(), b"/opt/proto-x"))
        sys.stderr.buffer.write(result.stderr.replace(str(base).encode(), b"/opt/proto-x"))
        return result.returncode
    if tool == "scp":
        values = ssh_args(args)
        source, target = values
        alias, remote = target.split(":", 1)
        if alias != "protox-test":
            return 91
        target = Path(mapped(remote))
        if os.environ.get("DEPLOY_CHECK_UPLOAD_FAIL"):
            target.write_bytes(b"partial")
            return 1
        shutil.copyfile(source, target)
        if os.environ.get("DEPLOY_CHECK_BAD_HASH"):
            with target.open("ab") as output:
                output.write(b"corruption")
        return 0
    if tool == "id":
        if args == ["-u"]:
            print("0")
            return 0
        if args == ["-u", "protox"]:
            if os.environ.get("DEPLOY_CHECK_NEW_ACCOUNT") and not (control / "user-created").exists():
                return 1
            print("1001")
            return 0
        return 91
    if tool == "uname":
        print("x86_64")
        return 0
    if tool == "getent":
        if os.environ.get("DEPLOY_CHECK_NEW_ACCOUNT"):
            marker = "group-created" if args[0] == "group" else "user-created"
            return 0 if (control / marker).exists() else 2
        return 0
    if tool in ("groupadd", "useradd"):
        (control / ("group-created" if tool == "groupadd" else "user-created")).touch()
        return 0
    if tool in ("chown", "sleep"):
        return 0
    if tool == "sha256sum":
        filenames = [value for value in args if not value.startswith("-")]
        lines = Path(filenames[0]).read_text().splitlines() if filenames else sys.stdin.read().splitlines()
        for line in lines:
            digest, name = line.split("  ", 1)
            if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
                return 1
        return 0
    if tool in ("mv", "cp"):
        marker = control / ("failed-" + tool)
        if tool == "mv" and os.environ.get("DEPLOY_CHECK_MOVE_FAIL") and not marker.exists():
            if "/tree/server.key" in " ".join(args):
                marker.touch()
                return 1
        if tool == "cp" and os.environ.get("DEPLOY_CHECK_BACKUP_FAIL") and not marker.exists():
            if "/backups/" in args[-1]:
                marker.touch()
                return 1
        return subprocess.run(["/bin/" + tool] + args).returncode
    if tool != "systemctl":
        return 91

    state_file = control / "state.json"
    state = json.loads(state_file.read_text())
    action = args[0]
    code = 0
    if action == "show":
        prop = next(item.split("=", 1)[1] for item in args if item.startswith("--property="))
        if prop == "LoadState":
            print("loaded" if unit.exists() else "not-found")
        elif prop == "MainPID":
            print(state["pid"])
        elif prop == "NRestarts":
            print(state["restarts"])
        else:
            return 91
    elif action == "is-enabled":
        enabled = state["enabled"] if unit.exists() else "not-found"
        print(enabled)
        code = 0 if enabled in ("enabled", "enabled-runtime") else 1
    elif action == "is-active":
        if state["generation"] == "new" and state["active"]:
            state["checks"] += 1
            if os.environ.get("DEPLOY_CHECK_POLICY") == "late-crash" and state["checks"] >= 2:
                state["active"], state["pid"] = False, 0
            if os.environ.get("DEPLOY_CHECK_POLICY") == "restart-loop" and state["checks"] >= 2:
                state["pid"] += 1
                state["restarts"] += 1
        code = 0 if state["active"] else 3
    elif action in ("enable", "disable"):
        if not unit.exists():
            return 1
        state["enabled"] = ("enabled-runtime" if "--runtime" in args else "enabled") if action == "enable" else "disabled"
    elif action == "stop":
        if not unit.exists():
            return 5
        state["active"], state["pid"] = False, 0
    elif action in ("restart", "start"):
        if not unit.exists() or not (base / "protox").exists():
            return 5
        generation = "new" if (base / "protox").read_bytes().startswith(b"new-binary") else "old"
        state["generation"] = generation
        state["checks"] = 0
        state["starts"].append({"generation": generation, "files": snapshot(base), "action": action})
        policy = os.environ.get("DEPLOY_CHECK_POLICY", "healthy")
        failed = generation == "new" and policy in ("restart-error", "restore-failure")
        failed = failed or generation == "old" and policy == "restore-failure"
        state["active"] = not failed
        state["pid"] = (200 if generation == "new" else 100) if not failed else 0
        state["restarts"] = 0
        code = 1 if failed else 0
    elif action != "daemon-reload":
        return 91
    state_file.write_text(json.dumps(state))
    return code


def snapshot(root):
    result = {}
    for name in ASSETS:
        item = root / name
        if item.is_file():
            result[name] = hashlib.sha256(item.read_bytes()).hexdigest()
        elif item.is_dir():
            result[name + "/"] = "directory"
            for child in sorted(item.rglob("*")):
                relative = child.relative_to(root).as_posix()
                if child.is_file():
                    result[relative] = hashlib.sha256(child.read_bytes()).hexdigest()
                elif child.is_dir():
                    result[relative + "/"] = "directory"
    return result


class DeployChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private = REPO / ".local"
        private.mkdir(exist_ok=True)
        cls.fixture_directory = tempfile.TemporaryDirectory(prefix="deploy-checks-", dir=private)
        cls.run_root = Path(cls.fixture_directory.name)
        cls.cert = cls.run_root / "fixture.crt"
        cls.key = cls.run_root / "fixture.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-subj", "/CN=cover.example", "-days", "1", "-keyout", str(cls.key), "-out", str(cls.cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_directory.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=self.run_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "bin").mkdir()
        shutil.copyfile(REPO / "scripts/deploy-test.sh", self.repo / "scripts/deploy-test.sh")
        shutil.copyfile(REPO / "scripts/protox.service", self.repo / "scripts/protox.service")
        (self.repo / "bin/protox-linux-amd64").write_text("new-binary\n")
        self.private = self.repo / ".local/private config"
        self.private.mkdir(parents=True)
        (self.repo / ".local/ssh_config").write_text("Host protox-test\n    HostName 192.0.2.1\n")
        shutil.copyfile(self.cert, self.private / "server.crt")
        shutil.copyfile(self.key, self.private / "server.key")
        (self.private / "token").write_text("42" * 32 + "\n")
        (self.private / "cover/sub").mkdir(parents=True)
        (self.private / "cover/index.html").write_text("new public site")
        (self.private / "cover/sub/a b.txt").write_text("public asset with a space")
        (self.private / "cover/package.sha256").write_text("ordinary public filename")
        self.config = {"cert_file": "server.crt", "key_file": "server.key", "token_file": "token",
                       "cover_dir": "cover", "web_listen": ":14443", "http3_listen": ":14443"}
        self.write_config()
        self.remote = self.root / "remote"
        self.base = self.remote / "opt/proto-x"
        (self.remote / "opt").mkdir(parents=True)
        self.unit = self.remote / "etc/systemd/system/protox.service"
        self.unit.parent.mkdir(parents=True)
        self.control = self.remote / "control"
        self.control.mkdir()
        self.state_path = self.control / "state.json"
        self.state_path.write_text(json.dumps({"active": False, "enabled": "not-found", "pid": 0,
                                              "restarts": 0, "generation": "absent", "checks": 0, "starts": []}))
        (self.remote / "etc/ssh").mkdir()
        (self.remote / "etc/ssh/management-sentinel").write_text("preserve management")
        self.mock_bin = self.root / "mock-bin"
        self.mock_bin.mkdir()
        wrapper = self.mock_bin / "mock-tool"
        wrapper.write_text("#!" + sys.executable + "\nimport os, runpy, sys\nsys.argv[1:1] = ['--mock-tool', os.path.basename(sys.argv[0])]\nrunpy.run_path(" + repr(str(Path(__file__).resolve())) + ", run_name='__main__')\n")
        wrapper.chmod(0o755)
        for command in ("ssh", "scp", "id", "uname", "getent", "groupadd", "useradd", "chown", "sleep", "sha256sum", "systemctl", "mv", "cp"):
            (self.mock_bin / command).symlink_to(wrapper.name)
        self.env = dict(os.environ, PATH=str(self.mock_bin) + os.pathsep + os.environ["PATH"], DEPLOY_CHECK_ROOT=str(self.remote))

    def write_config(self):
        (self.private / "server.json").write_text(json.dumps(self.config))

    def old_install(self, active=True, enabled="enabled", optional=True):
        self.base.mkdir(exist_ok=True)
        for name in ("protox", "server.json", "server.crt", "server.key", "token"):
            (self.base / name).write_text("old-" + name)
            (self.base / name).chmod(0o640)
        (self.base / "protox").chmod(0o755)
        (self.base / "cover").mkdir()
        (self.base / "cover/obsolete.html").write_text("old cover only")
        if optional:
            for name in ("ech-keys.json", "ech-config.bin", "ca.crt", "ca.pem"):
                (self.base / name).write_text("old-" + name)
        (self.base / "staging").mkdir()
        (self.base / "staging/ech-keys.json").write_text("stale upload must be ignored")
        (self.base / "experiments").mkdir()
        (self.base / "experiments/sentinel").write_text("preserve unrelated data")
        self.unit.write_text("old unit")
        self.state_path.write_text(json.dumps({"active": active, "enabled": enabled, "pid": 100 if active else 0,
                                              "restarts": 0, "generation": "old", "checks": 0, "starts": []}))
        return snapshot(self.base)

    def deploy(self, **overrides):
        environment = dict(self.env, **overrides)
        result = subprocess.run(["sh", "scripts/deploy-test.sh", ".local/ssh_config", "protox-test", str(self.private)],
                                cwd=self.repo, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual((self.remote / "etc/ssh/management-sentinel").read_text(), "preserve management")
        self.assertFalse(list((self.repo / ".local").glob("deploy-package.*")), "private local package was not cleaned")
        for call in self.calls():
            if call[0] in ("ssh", "scp"):
                self.assertIn("StrictHostKeyChecking=yes", call)
                self.assertIn("BatchMode=yes", call)
            if call[0] == "systemctl":
                self.assertTrue(call[1] == "daemon-reload" or "protox.service" in call)
        return result

    def calls(self):
        file = self.control / "calls.jsonl"
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def state(self):
        return json.loads(self.state_path.read_text())

    def backups(self):
        return sorted((self.base / "backups").glob("*"))

    def assert_clean_stage(self):
        self.assertFalse(list(self.base.glob(".upload.*")))
        self.assertFalse((self.base / ".deploy-lock").exists())

    def assert_restored(self, previous, active=True, enabled="enabled"):
        self.assertEqual(snapshot(self.base), previous)
        self.assertEqual(self.unit.read_text(), "old unit")
        self.assertEqual(self.state()["active"], active)
        self.assertEqual(self.state()["enabled"], enabled)
        self.assertEqual(snapshot(self.backups()[0] / "files"), previous)
        self.assertEqual((self.base / "experiments/sentinel").read_text(), "preserve unrelated data")
        self.assert_clean_stage()

    def test_first_install_with_optional_assets(self):
        (self.private / "ech-keys.json").write_text("[]")
        (self.private / "ech-config.bin").write_bytes(b"\x00\x00")
        shutil.copyfile(self.cert, self.private / "ca.pem")
        original = (self.private / "server.json").read_bytes()
        result = self.deploy(DEPLOY_CHECK_NEW_ACCOUNT="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.state()["active"])
        self.assertEqual(self.state()["enabled"], "enabled")
        self.assertTrue((self.control / "group-created").exists())
        self.assertTrue((self.control / "user-created").exists())
        for name in ("ech-keys.json", "ech-config.bin", "ca.crt", "cover/index.html"):
            self.assertTrue((self.base / name).is_file())
        self.assertEqual((self.private / "server.json").read_bytes(), original)
        self.assertEqual((self.backups()[0] / "had-unit").read_text().strip(), "no")
        self.assertEqual(snapshot(self.backups()[0] / "files"), {})
        self.assertEqual(stat.S_IMODE((self.base / "server.key").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((self.base / "cover").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.base / "protox").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.unit.stat().st_mode), 0o644)
        self.assertIn("cover/package.sha256", (self.base / "package.sha256").read_text())
        self.assertGreaterEqual(self.state()["checks"], 6)
        self.assert_clean_stage()

    def test_upgrade_removes_old_optional_assets_and_ignores_stale_stage(self):
        previous = self.old_install()
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("ech-keys.json", "ech-config.bin", "ca.crt", "ca.pem", "cover/obsolete.html"):
            self.assertFalse((self.base / name).exists())
        self.assertEqual(snapshot(self.backups()[0] / "files"), previous)
        self.assertEqual((self.base / "experiments/sentinel").read_text(), "preserve unrelated data")
        self.assertEqual((self.base / "staging/ech-keys.json").read_text(), "stale upload must be ignored")
        self.assert_clean_stage()

    def test_custom_asset_paths_normalize_without_modifying_source(self):
        (self.private / "certs").mkdir()
        for name in ("server.crt", "server.key"):
            (self.private / name).rename(self.private / "certs" / name)
        self.config["cert_file"] = "certs/server.crt"
        self.config["key_file"] = "/opt/proto-x/certs/server.key"
        self.config["token_file"] = str(self.private / "token")
        self.write_config()
        source = (self.private / "server.json").read_bytes()
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        deployed = json.loads((self.base / "server.json").read_text())
        self.assertEqual([deployed[k] for k in ("cert_file", "key_file", "token_file")], ["server.crt", "server.key", "token"])
        self.assertEqual((self.private / "server.json").read_bytes(), source)

    def test_restart_error_restores_runtime_enabled_package(self):
        previous = self.old_install(enabled="enabled-runtime")
        result = self.deploy(DEPLOY_CHECK_POLICY="restart-error")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("previous package and service state restored", result.stderr)
        self.assert_restored(previous, enabled="enabled-runtime")

    def test_late_exit_after_successful_restart_restores_old_package(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_POLICY="late-crash")
        self.assertNotEqual(result.returncode, 0)
        self.assert_restored(previous)

    def test_active_restart_loop_is_rejected(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_POLICY="restart-loop")
        self.assertNotEqual(result.returncode, 0)
        self.assert_restored(previous)

    def test_partial_file_install_is_restored(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_MOVE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assert_restored(previous)
        starts = self.state()["starts"]
        self.assertEqual([entry["generation"] for entry in starts], ["old"])

    def test_first_install_failure_removes_new_unit_and_files(self):
        result = self.deploy(DEPLOY_CHECK_POLICY="late-crash", DEPLOY_CHECK_NEW_ACCOUNT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), {})
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.state()["active"])
        self.assert_clean_stage()

    def test_first_install_failure_before_unit_exists_is_cleaned(self):
        result = self.deploy(DEPLOY_CHECK_MOVE_FAIL="1", DEPLOY_CHECK_NEW_ACCOUNT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), {})
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.state()["active"])
        self.assert_clean_stage()

    def test_inactive_disabled_service_remains_inactive_after_rollback(self):
        previous = self.old_install(active=False, enabled="disabled")
        result = self.deploy(DEPLOY_CHECK_POLICY="restart-error")
        self.assertNotEqual(result.returncode, 0)
        self.assert_restored(previous, active=False, enabled="disabled")
        self.assertFalse(any(item["generation"] == "old" for item in self.state()["starts"]))

    def test_backup_failure_never_stops_old_service(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_BACKUP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertTrue(self.state()["active"])
        self.assertEqual(self.backups(), [])
        self.assertFalse(any(call[:2] == ["systemctl", "stop"] for call in self.calls()))
        self.assert_clean_stage()

    def test_partial_upload_is_cleaned_before_any_service_change(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_UPLOAD_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "systemctl" for call in self.calls()))
        self.assert_clean_stage()

    def test_corrupt_archive_never_changes_installed_files(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_BAD_HASH="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "systemctl" for call in self.calls()))
        self.assert_clean_stage()

    def test_existing_lock_is_preserved(self):
        previous = self.old_install()
        lock = self.base / ".deploy-lock"
        lock.mkdir()
        (lock / "pid").write_text("other installer")
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertEqual((lock / "pid").read_text(), "other installer")
        self.assertFalse(list(self.base.glob(".upload.*")))

    def test_missing_referenced_asset_is_rejected(self):
        previous = self.old_install()
        self.config["ech_keys_file"] = "missing-keys.json"
        self.write_config()
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_web_config_without_public_root_is_rejected(self):
        previous = self.old_install()
        self.config.pop("cover_dir")
        self.write_config()
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_configured_private_key_inside_cover_is_rejected(self):
        previous = self.old_install()
        shutil.copyfile(self.private / "server.key", self.private / "cover/private.key")
        self.config["key_file"] = "cover/private.key"
        self.write_config()
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_parent_traversal_in_asset_path_is_rejected(self):
        previous = self.old_install()
        self.config["token_file"] = "../private config/token"
        self.write_config()
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_symlink_in_public_tree_is_rejected(self):
        previous = self.old_install()
        (self.private / "cover/key").symlink_to(self.private / "server.key")
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_incorrect_key_certificate_pair_is_rejected(self):
        previous = self.old_install()
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(self.private / "server.key")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(any(call[0] == "scp" for call in self.calls()))

    def test_failed_automatic_restore_returns_three_and_keeps_recovery_state(self):
        previous = self.old_install()
        result = self.deploy(DEPLOY_CHECK_POLICY="restore-failure")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("AUTOMATIC RESTORE FAILED", result.stderr)
        self.assertEqual(snapshot(self.base), previous)
        self.assertFalse(self.state()["active"])
        self.assertTrue((self.base / ".deploy-lock/backup").exists())
        self.assertEqual(len(list(self.base.glob(".upload.*"))), 1)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--mock-tool":
        sys.exit(mock_tool(sys.argv[2], sys.argv[3:]))
    unittest.main(verbosity=2)
