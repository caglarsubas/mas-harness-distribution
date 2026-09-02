from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.airgap import AirgapError, MAX_FILE_BYTES, import_archive
from tests.signing.helpers import NOW


def archive_with(root: Path, members: list[tuple[tarfile.TarInfo, bytes]], *, format: int = tarfile.USTAR_FORMAT) -> tuple[Path, str]:
    path = root / "hostile.tar"
    with tarfile.open(path, "w", format=format) as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data))
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return path, digest


def regular(name: str, data: bytes = b"{}\n") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info, data


class ArchiveSecurityTests(unittest.TestCase):
    def assert_refused(self, members: list[tuple[tarfile.TarInfo, bytes]], code: str, *, format: int = tarfile.USTAR_FORMAT) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, digest = archive_with(root, members, format=format)
            destination = root / "imported"
            with self.assertRaisesRegex(AirgapError, code):
                import_archive(archive, digest, destination, NOW)
            self.assertFalse(destination.exists())

    def test_traversal_absolute_backslash_and_unicode_paths_are_rejected(self) -> None:
        for name in ("../escape", "/absolute", "payload\\escape", "payload/évidence"):
            with self.subTest(name=name):
                self.assert_refused([regular(name)], "ARCHIVE_PATH_INVALID")

    def test_links_and_special_members_are_rejected(self) -> None:
        for member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            info, data = regular("payload/member")
            info.type = member_type
            info.linkname = "payload/other" if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
            info.size = 0
            with self.subTest(member_type=member_type):
                self.assert_refused([(info, b"")], "ARCHIVE_MEMBER_INVALID")

    def test_duplicate_members_are_rejected(self) -> None:
        self.assert_refused([regular("payload/same"), regular("payload/same")], "ARCHIVE_DUPLICATE_PATH")

    def test_oversized_member_is_rejected(self) -> None:
        data = b"x" * (MAX_FILE_BYTES + 1)
        self.assert_refused([regular("payload/large", data)], "ARCHIVE_FILE_TOO_LARGE")

    def test_pax_metadata_is_rejected(self) -> None:
        info, data = regular("payload/member")
        info.pax_headers = {"comment": "unexpected"}
        self.assert_refused([(info, data)], "ARCHIVE_MEMBER_INVALID", format=tarfile.PAX_FORMAT)


if __name__ == "__main__":
    unittest.main()
