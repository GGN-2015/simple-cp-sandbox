from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from simple_cp_sandbox import SandboxConfig, run_executable


class SandboxApiTests(unittest.TestCase):
    def test_config_defaults_are_restrictive(self) -> None:
        config = SandboxConfig()

        self.assertTrue(config.block_filesystem_writes)
        self.assertTrue(config.block_network)
        self.assertTrue(config.block_privilege_escalation)
        self.assertTrue(config.refuse_root)
        self.assertEqual(config.read_deny_paths, ())
        self.assertEqual(config.write_allow_paths, ())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only sandbox integration")
    def test_linux_allows_stdout_and_denies_file_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "blocked.txt"
            script = (
                "import pathlib; "
                "print('hello'); "
                f"pathlib.Path({str(target)!r}).write_text('nope')"
            )

            result = run_executable(sys.executable, ["-c", script], timeout=5)

            self.assertEqual(result.stdout, b"hello\n")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only sandbox integration")
    def test_linux_allows_file_write_under_allowlisted_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allowed_dir = Path(directory) / "allowed"
            blocked_dir = Path(directory) / "blocked"
            allowed_dir.mkdir()
            blocked_dir.mkdir()
            allowed_target = allowed_dir / "ok.txt"
            blocked_target = blocked_dir / "no.txt"
            script = (
                "import pathlib; "
                f"pathlib.Path({str(allowed_target)!r}).write_text('ok'); "
                f"pathlib.Path({str(allowed_dir / 'child')!r}).mkdir(); "
                f"pathlib.Path({str(blocked_target)!r}).write_text('no')"
            )

            config = SandboxConfig(write_allow_paths=(allowed_dir,))
            result = run_executable(sys.executable, ["-c", script], timeout=5, config=config)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(allowed_target.read_text(), "ok")
            self.assertTrue((allowed_dir / "child").is_dir())
            self.assertFalse(blocked_target.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only sandbox integration")
    def test_linux_denies_reads_under_blacklisted_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            readable = Path(directory) / "public.txt"
            secret_dir = Path(directory) / "secret"
            secret_dir.mkdir()
            secret = secret_dir / "secret.txt"
            readable.write_text("public")
            secret.write_text("secret")
            script = (
                "import pathlib; "
                f"print(pathlib.Path({str(readable)!r}).read_text()); "
                f"pathlib.Path({str(secret)!r}).read_text()"
            )

            config = SandboxConfig(read_deny_paths=(secret_dir,))
            result = run_executable(sys.executable, ["-c", script], timeout=5, config=config)

            self.assertEqual(result.stdout, b"public\n")
            self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only sandbox integration")
    def test_linux_timeout_kills_process_group(self) -> None:
        result = run_executable(sys.executable, ["-c", "while True: pass"], timeout=0.2)

        self.assertTrue(result.timed_out)
        self.assertTrue(result.killed)


if __name__ == "__main__":
    unittest.main()
