"""検査漏れと、未検査の内容が配置される不具合の回帰テスト。"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scan_github_repository.policy import ADDED_RULES, DEFAULT_DIRECTORY, load_policy
from scan_github_repository.scanner import scan
from scan_github_repository.sync_package import SyncError, sync
from scan_github_repository.vendor import scanner_config as config
from scan_github_repository.vendor.repository_scanner import PackageIntelDB, parse_requirement_string


class ScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        data = self.root / "data"
        data.mkdir()
        # 実データのダウンロードに依存せず、判定ルールを検証するための最小入力。
        (data / "malicious_packages.csv").write_text(
            "package,policy,versions,ranges,sources\n"
            "0-8,versions_only,0.0.0.1,,test\n"
            "aaiohttp,versions_only,,,test\n"
            "slogsec,all_versions,,,test\n"
            "frint,all_versions,,,test\n"
            "skytext,all_versions,,,test\n"
            "logcrypt.cryptography,all_versions,,,test\n",
            encoding="utf-8",
        )
        environment = patch.dict(os.environ, SCAN_GITHUB_REPOSITORY_DATA_DIR=str(data))
        environment.start()
        self.addCleanup(environment.stop)

    def test_utf16_inside_previously_skipped_directory(self):
        hidden = self.target / "env"
        hidden.mkdir()
        (hidden / "requirements.txt").write_text("0-8==0.0.0.1\n", encoding="utf-16")
        result = scan(self.target)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertTrue(result["blocked"])

    def test_local_requirements_includes_and_remote_reference(self):
        (self.target / "requirements.txt").write_text("-r first.lst\n", encoding="utf-8")
        (self.target / "first.lst").write_text("--constraint=second.lst\n", encoding="utf-8")
        (self.target / "second.lst").write_text("0-8==0.0.0.1\n", encoding="utf-8")
        self.assertEqual(scan(self.target)["verdict"], "MALICIOUS")
        (self.target / "first.lst").write_text("-r https://example.invalid/remote.txt\n", encoding="utf-8")
        result = scan(self.target)
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["stats"]["unresolved_requirement_includes"], 1)

    def test_max_depth_scans_boundary_files_and_marks_skipped_subtree(self):
        nested = self.target / "vendor" / "package"
        nested.mkdir(parents=True)
        (nested.parent / "README.txt").write_text("checked on the boundary\n", encoding="utf-8")
        (nested / "requirements.txt").write_text("0-8==0.0.0.1\n", encoding="utf-8")
        (self.target / ".git").mkdir()
        capped = scan(self.target, max_depth=1)
        self.assertEqual(capped["max_depth"], 1)
        self.assertTrue(capped["incomplete"])
        self.assertEqual(capped["stats"]["text_files_scanned"], 1)
        self.assertEqual(capped["stats"]["directories_skipped_depth"], 1)
        self.assertEqual(capped["verdict"], "NO_FINDINGS")
        complete = scan(self.target, max_depth=2)
        self.assertEqual(complete["verdict"], "MALICIOUS")
        self.assertFalse(complete["incomplete"])
        self.assertEqual(scan(self.target)["findings"], complete["findings"])

    def test_requirements_include_cannot_bypass_max_depth(self):
        nested = self.target / "vendor"
        nested.mkdir()
        (self.target / "requirements.txt").write_text("-r vendor/packages.lst\n", encoding="utf-8")
        (nested / "packages.lst").write_text("0-8==0.0.0.1\n", encoding="utf-8")
        command = [sys.executable, "-m", "scan_github_repository.scan_cli", "--max-depth", "0", str(self.target)]
        process = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 2, process.stdout)
        result = json.loads(process.stdout)
        self.assertEqual(result["reason"], "scan_incomplete")
        self.assertEqual(result["stats"]["requirement_includes_skipped_depth"], 1)
        self.assertEqual(result["findings"], [])
        self.assertEqual(scan(self.target)["verdict"], "MALICIOUS")

    def test_archive_and_lfs_force_incomplete_scan(self):
        with zipfile.ZipFile(self.target / "renamed.dat", "w") as archive:
            archive.writestr("README", "content")
        (self.target / "object.bin").write_text(
            "version https://git-lfs.github.com/spec/v1\n", encoding="utf-8",
        )
        result = scan(self.target)
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["stats"]["files_skipped_archive"], 1)
        self.assertEqual(result["stats"]["files_skipped_lfs"], 1)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX special files")
    def test_links_and_pipes_are_not_opened(self):
        os.mkfifo(self.target / "pipe")
        (self.target / "link").symlink_to(self.root / "missing")
        result = scan(self.target)
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["stats"]["files_skipped_special"], 1)
        self.assertEqual(result["stats"]["files_skipped_link"], 1)

    def test_package_version_matching(self):
        intel = PackageIntelDB()
        intel.add_rule("sample", config.POLICY_VERSIONS_ONLY, ["1.0", "2.0a1"], [">=3,<5"])
        for requirement, expected in (
            ("sample==1.0.0", "MALICIOUS"),
            ("sample>=2.0a1,<2.0b1", "SUSPICIOUS"),
            ("sample>=3.5,<4.5", "SUSPICIOUS"),
        ):
            with self.subTest(requirement=requirement):
                ref = parse_requirement_string(requirement, "requirements.txt", 1, "requirements")
                self.assertEqual(intel.evaluate(ref)[0], expected)
        (self.target / "requirements.txt").write_text("aaiohttp==1\n", encoding="utf-8")
        self.assertEqual(scan(self.target)["verdict"], "SUSPICIOUS")

    def test_versions_only_reports_exact_pins_and_possible_range_overlap(self):
        intel = self.root / "intel.csv"
        intel.write_text(
            "package,policy,versions,ranges,sources\n"
            'scan-clone-version-demo,versions_only,1.4.2,">=2,<3",test\n',
            encoding="utf-8",
        )
        for specifier, verdict in (
            ("==1.4.2,>=1.4", "MALICIOUS"),
            ("==2.2", "MALICIOUS"),
            ("==3", "NO_FINDINGS"),
            ("==1.4.2+internal", "NO_FINDINGS"),
            (">=3,<4", "NO_FINDINGS"),
            ("==2.2,!=2.2", "NO_FINDINGS"),
            (">=2.8,<4", "SUSPICIOUS"),
            ("", "SUSPICIOUS"),
        ):
            with self.subTest(specifier=specifier):
                (self.target / "requirements.txt").write_text(
                    f"scan-clone-version-demo{specifier}\n", encoding="utf-8",
                )
                result = scan(self.target, intel_csv=intel)
                self.assertEqual(result["verdict"], verdict)
                if result["findings"]:
                    self.assertTrue(result["findings"][0]["dependency"].startswith("scan-clone-version-demo"))

    def test_additional_feed_does_not_widen_version_scope(self):
        intel = self.root / "intel.csv"
        intel.write_text(
            "package,policy,versions,ranges,sources\n"
            "0-8,all_versions,,,broad feed\n"
            "0-8,versions_only,0.0.0.2,,precise feed\n",
            encoding="utf-8",
        )
        target = self.target / "requirements.txt"
        for version, verdict in (("0.0.0.1", "MALICIOUS"), ("0.0.0.2", "MALICIOUS"), ("0.0.0.3", "NO_FINDINGS")):
            with self.subTest(version=version):
                target.write_text(f"0-8=={version}\n", encoding="utf-8")
                result = scan(self.target, intel_csv=intel)
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["intel_scope_conflicts"], ["0-8"])

    def test_new_install_requires_a_local_database_before_cloning(self):
        process = subprocess.run(
            [sys.executable, "-m", "scan_github_repository", "--data-dir", str(self.root / "empty"),
             str(self.root / "not-a-repository"), str(self.root / "dest")],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(process.returncode, 2, process.stdout)
        self.assertEqual(json.loads(process.stdout)["reason"], "missing_intelligence")
        self.assertFalse((self.root / "dest").exists())

    def test_sync_ignores_withdrawn_reports_and_preserves_old_data_on_failure(self):
        data = self.root / "synced"
        archive_path = self.root / "advisories.zip"
        manifest = self.root / "datadog.json"
        advisory = {"id": "MAL-2026-1", "affected": [{
            "package": {"ecosystem": "PyPI", "name": "sync-test-demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0"}, {"fixed": "2.0"},
            ]}],
        }]}
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("MAL-2026-1.json", json.dumps(advisory))
            archive.writestr("MAL-2026-2.json", json.dumps({
                **advisory, "id": "MAL-2026-2", "withdrawn": "2026-01-01T00:00:00Z",
            }))
            archive.writestr("GHSA-example.json", "{}")
        manifest.write_text('{"sync-test-demo":null,"sync-test-new":["3.0"]}', encoding="utf-8")
        stats = sync(data, osv_archive=archive_path, datadog_manifest=manifest)
        self.assertEqual(stats["counts"]["withdrawn_reports"], 1)
        self.assertEqual(stats["scope_conflicts"], 1)
        target = self.target / "requirements.txt"
        for version, verdict in (("2.0rc1", "MALICIOUS"), ("2.0", "NO_FINDINGS")):
            target.write_text(f"sync-test-demo=={version}\n", encoding="utf-8")
            self.assertEqual(scan(self.target, data_dir=data)["verdict"], verdict)
        previous = (data / "malicious_packages.csv").read_bytes()
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("unrelated.json", "{}")
        with self.assertRaises(SyncError):
            sync(data, osv_archive=archive_path)
        self.assertEqual((data / "malicious_packages.csv").read_bytes(), previous)

    def test_external_artifact_name_is_not_proof_of_registry_version(self):
        target = self.target / "requirements.txt"
        for requirement, verdict in (
            ("frint @ git+https://example.org/local-fork.git", "SUSPICIOUS"),
            ("0-8 @ https://files.pythonhosted.org/packages/0_8-0.0.0.1-py3-none-any.whl", "MALICIOUS"),
            ("0-8 @ https://files.pythonhosted.org/packages/0_8-0.0.0.2-py3-none-any.whl", "NO_FINDINGS"),
        ):
            with self.subTest(requirement=requirement):
                target.write_text(requirement + "\n", encoding="utf-8")
                self.assertEqual(scan(self.target)["verdict"], verdict)

    def test_intelligence_csv_and_invalid_file(self):
        (self.target / "requirements.txt").write_text("scan-clone-regression-demo==1\n", encoding="utf-8")
        intel = self.root / "intel.csv"
        intel.write_text(
            "package,policy,versions,ranges,sources\n"
            "scan-clone-regression-demo,all_versions,,,test\n",
            encoding="utf-8",
        )
        before = scan(self.target)
        after = scan(self.target, intel_csv=intel)
        self.assertEqual(before["verdict"], "NO_FINDINGS")
        self.assertEqual(after["verdict"], "MALICIOUS")
        self.assertNotEqual(before["rules_sha256"], after["rules_sha256"])
        intel.write_text("wrong\n", encoding="utf-8")
        process = subprocess.run(
            [sys.executable, "-m", "scan_github_repository.scan_cli", "--intel-csv", str(intel), str(self.target)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout)["reason"], "invalid_intelligence")

    def test_malicious_imports_and_local_name_collision(self):
        text = (
            "import slogsec\nimport frint as helper\n"
            "from logcrypt import cryptography\nfrom skytext import colour\n"
            "# import skytext\nexample = 'import frint'\nfrom . import frint\n"
        )
        (self.target / "poc.py").write_text(text, encoding="utf-8")
        (self.target / "src").mkdir()
        (self.target / "src" / "frint.py").write_text("# local helper\n", encoding="utf-8")
        report = scan(self.target)
        self.assertEqual(report["verdict"], "MALICIOUS")
        findings = [f for f in report["findings"] if f["category"] == "known_malicious_import"]
        self.assertEqual([f["line"] for f in findings], [1, 3, 4])

    def test_shortener_reference_and_download_are_distinct(self):
        (self.target / "vendor.php").write_text(
            "'default' => null, // API reference http://goo.gl/example\n",
            encoding="utf-8",
        )
        (self.target / "README.md").write_text(
            "[Download](https://tinyurl.com/sample)\n"
            "[Download](https://example.org/package) and see bit.ly/reference\n", encoding="utf-8",
        )
        result = scan(self.target)
        self.assertEqual(
            {(f["file"], f["line"]): (f["category"], f["blocking"]) for f in result["findings"]},
            {("vendor.php", 1): ("shortened_url_reference", False),
             ("README.md", 1): ("shortened_url", True),
             ("README.md", 2): ("shortened_url_reference", False)},
        )
        self.assertEqual(len(result["findings"]), 3)

    def test_legacy_policy_inherits_severity_switches_for_new_rules(self):
        policy_dir = self.root / "policy"
        policy_dir.mkdir()
        for file in DEFAULT_DIRECTORY.glob("*.toml"):
            lines = file.read_text(encoding="utf-8").splitlines()
            policy = "\n".join(line for line in lines if line.partition(" = ")[0] not in ADDED_RULES)
            (policy_dir / file.name).write_text(policy, encoding="utf-8")
        info = policy_dir / "info.toml"
        info.write_text(info.read_text(encoding="utf-8").replace("block = false", "block = true"), encoding="utf-8")
        self.assertTrue(load_policy(policy_dir).rules["remote_shell_example"].block)

    def test_remote_pipeline_ignores_comments_assignments_and_examples(self):
        (self.target / "README.md").write_text(
            "`curl https://example.org/setup.sh | sudo bash`\n", encoding="utf-8",
        )
        (self.target / "run.sh").write_text(
            "# curl https://example.org/setup.sh | bash\n"
            "EXAMPLE='curl https://example.org/setup.sh | bash'\n"
            "echo '<<NOT_A_HEREDOC'\n"
            "cat <<'EXAMPLE'\ncurl https://example.org/setup.sh | bash\nEXAMPLE\n"
            "curl https://example.org/setup.sh '|' bash\n"
            "echo \"example:\ncurl https://example.org/setup.sh | bash\n\"\n"
            "curl 'https://example.org/setup.sh' \\\n"
            " | sudo -n /bin/bash\n",
            encoding="utf-8",
        )
        findings = scan(self.target)["findings"]
        self.assertEqual(
            [(f["category"], f["line"], f["blocking"]) for f in findings],
            [("remote_shell_pipeline", 11, True), ("remote_shell_example", 1, False)],
        )

    def test_remote_pipeline_can_run_inside_shell_condition(self):
        (self.target / "run.sh").write_text(
            "if curl https://example.org/setup.sh | bash; then\n"
            "  echo done\n"
            "fi\n",
            encoding="utf-8",
        )
        self.assertEqual(
            [f["category"] for f in scan(self.target)["findings"]], ["remote_shell_pipeline"],
        )

    def test_elf_and_pe_are_detected_independently_of_extension(self):
        (self.target / "kernel").write_bytes(b"\x7fELF\x02\x01" + bytes(58))
        pe = bytearray(128)
        pe[:2] = b"MZ"
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\0\0"
        (self.target / "attachment.dat").write_bytes(pe)
        (self.target / "note.txt").write_text("MZ is only a prefix.\n", encoding="utf-8")
        result = scan(self.target)
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["stats"]["files_skipped_elf"], 1)
        self.assertEqual(result["stats"]["files_skipped_pe"], 1)
        self.assertEqual(result["stats"]["files_skipped_unreadable_text"], 0)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("git"), "requires Linux and Git")
    def test_clone_publishes_exact_commit_and_blocks_unresolved_content(self):
        def git(*args):
            return subprocess.check_output(
                ["git", "-C", str(self.target), *args], text=True, timeout=15,
            ).strip()

        def commit():
            git("add", ".")
            git("-c", "user.email=test@example.org", "-c", "user.name=Test",
                "-c", "commit.gpgsign=false", "commit", "-qm", "test")
            return git("rev-parse", "HEAD")

        def clone(destination, *options):
            return subprocess.run(
                [sys.executable, "-m", "scan_github_repository", *options, str(self.target), str(destination)],
                capture_output=True, text=True, timeout=45,
            )

        git("init", "-q")
        (self.target / "README.md").write_text("hello\n", encoding="utf-8")
        commit_id = commit()
        published = self.root / "published"
        result = clone(published)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(result.stdout)["commit"], commit_id)
        self.assertEqual(git("--git-dir", str(published / ".git"), "rev-parse", "HEAD"), commit_id)
        blocked = self.root / "blocked"
        package = self.target / "vendor"
        package.mkdir()
        (package / "README.md").write_text("package\n", encoding="utf-8")
        commit()
        limited = clone(blocked, "--max-depth", "0")
        self.assertEqual(limited.returncode, 2, limited.stdout)
        self.assertEqual(json.loads(limited.stdout)["stats"]["directories_skipped_depth"], 1)
        self.assertFalse(blocked.exists())
        (self.target / "requirements.txt").write_text("0-8==0.0.0.1\n", encoding="utf-8")
        commit()
        result = clone(blocked)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(blocked.exists())
        git("update-index", "--add", "--cacheinfo", f"160000,{commit_id},child")
        git("-c", "user.email=test@example.org", "-c", "user.name=Test",
            "-c", "commit.gpgsign=false", "commit", "-qm", "add gitlink")
        result = clone(blocked)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(json.loads(result.stdout)["unsupported"]["submodules"], 1)
        self.assertFalse(blocked.exists())
        self.assertFalse(list(self.root.glob(".scan-github-repository-*")))
