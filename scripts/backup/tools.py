"""Download ONLY reviewed, digest-pinned tool binaries. No install scripts."""
import hashlib
import io
import os
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

PINS = {
    "age-linux": ("https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz", "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"),
    "age-windows": ("https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip", "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7"),
    "rclone-linux": ("https://github.com/rclone/rclone/releases/download/v1.75.2/rclone-v1.75.2-linux-amd64.zip", "349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702"),
}


def install(root, windows=False):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    keys = ["age-windows"] if windows else ["age-linux", "rclone-linux"]
    for key in keys:
        url, expected = PINS[key]
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(64 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("tool_checksum")
        if key.startswith("age"):
            suffix = ".exe" if windows else ""
            names = [("age/age" + suffix, "age" + suffix), ("age/age-keygen" + suffix, "age-keygen" + suffix)]
        else:
            names = [("rclone-v1.75.2-linux-amd64/rclone", "rclone")]
        for member, output in names:
            if url.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    content = archive.read(member)
            else:
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                    content = archive.extractfile(member).read()
            path = root / output
            path.write_bytes(content)
            path.chmod(0o700)


if __name__ == "__main__":
    try:
        install(sys.argv[1], windows=os.name == "nt")
    except Exception:
        print("backup: tool_install_failed", file=sys.stderr)
        sys.exit(1)
