"""Create-exclusive publication: a concurrent writer can never be overwritten."""

from __future__ import annotations

import errno
import os
from pathlib import Path


def publish_directory(staging: Path, destination: Path, exists_code: str, error: type[ValueError]) -> None:
    """Claim ``destination`` with an exclusive mkdir, then atomically replace the empty claim."""
    try:
        os.mkdir(destination, 0o700)
    except FileExistsError as exc:
        raise error(exists_code) from exc
    except OSError as exc:
        raise error("ATOMIC_PUBLISH_FAILED") from exc
    try:
        os.replace(staging, destination)
    except OSError as exc:
        try:
            os.rmdir(destination)
        except OSError:
            pass
        raise error(exists_code if exc.errno in {errno.EEXIST, errno.ENOTEMPTY} else "ATOMIC_PUBLISH_FAILED") from exc


def publish_file(temporary: Path, destination: Path, exists_code: str, error: type[ValueError]) -> None:
    """Hard-link ``temporary`` to ``destination``; the link fails rather than replace an existing name."""
    try:
        os.link(temporary, destination)
    except FileExistsError as exc:
        raise error(exists_code) from exc
    except OSError as exc:
        raise error("ATOMIC_PUBLISH_FAILED") from exc
