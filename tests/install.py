"""Exercise the installer offline with release-shaped fixtures."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
PAYLOAD = b"#!/bin/sh\nprintf 'kompromat fixture\\n'\n"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "tools"
        self.assets = self.root / "assets"
        self.destination = self.root / "install with spaces"
        for directory in [self.bin, self.assets, self.root / "tmp"]:
            directory.mkdir()
        for tool in ["python3", "tar", "gzip", "mktemp", "awk", "cp", "chmod", "mv", "mkdir", "rm", "sha256sum", "shasum"]:
            executable = shutil.which(tool)
            if executable:
                (self.bin / tool).symlink_to(executable)
        self.write_tool("uname", '#!/bin/sh\ncase "$1" in -s) printf "%s\\n" "$TEST_OS";; -m) printf "%s\\n" "$TEST_ARCH";; esac\n')
        self.write_tool("curl", '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith("https://"))
asset = pathlib.Path(os.environ["TEST_ASSETS"]) / url.rsplit("/", 1)[1]
if not asset.exists():
    sys.exit(22)
shutil.copyfile(asset, args[args.index("-o") + 1])
''')
        self.env = dict(os.environ, PATH=str(self.bin), TMPDIR=str(self.root / "tmp"),
                        TEST_ASSETS=str(self.assets), KOMPROMAT_INSTALL_DIR=str(self.destination),
                        KOMPROMAT_RELEASE_BASE_URL="https://release.example/latest")

    def write_tool(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def release(self, target):
        archive = self.assets / f"kompromat-{target}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo("kompromat")
            member.size = len(PAYLOAD)
            member.mode = 0o755
            tar.addfile(member, io.BytesIO(PAYLOAD))
        checksum = archive.with_name(archive.name + ".sha256")
        checksum.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        return checksum

    def install(self, system="Linux", arch="x86_64"):
        result = subprocess.run(["/bin/sh", str(INSTALLER)], env=dict(self.env, TEST_OS=system, TEST_ARCH=arch), capture_output=True, text=True)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        return result

    def test_supported_platforms_download_and_install(self):
        for system, arch, target in [
            ("Linux", "x86_64", "x86_64-unknown-linux-musl"),
            ("Linux", "aarch64", "aarch64-unknown-linux-musl"),
            ("Darwin", "x86_64", "x86_64-apple-darwin"),
            ("Darwin", "arm64", "aarch64-apple-darwin"),
        ]:
            with self.subTest(target=target):
                self.release(target)
                result = self.install(system, arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                binary = self.destination / "kompromat"
                self.assertEqual(binary.read_bytes(), PAYLOAD)
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)

    def test_bad_checksum_preserves_existing_install(self):
        checksum = self.release("x86_64-unknown-linux-musl")
        checksum.write_text("0" * 64 + "  archive.tar.gz\n")
        self.destination.mkdir()
        binary = self.destination / "kompromat"
        binary.write_bytes(b"existing installation")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertEqual(binary.read_bytes(), b"existing installation")

    def test_shasum_fallback(self):
        (self.bin / "sha256sum").unlink(missing_ok=True)
        if not (self.bin / "shasum").exists():
            self.skipTest("shasum unavailable")
        self.release("x86_64-unknown-linux-musl")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_release_and_unsupported_platform_fail(self):
        self.assertNotEqual(self.install().returncode, 0)
        result = self.install("Windows", "x86_64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported platform", result.stderr)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
