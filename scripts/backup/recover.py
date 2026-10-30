"""Owner-assisted, offline recovery drill. Never accepts a hosted destination."""
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from backup import Failure, require, verify_bundle
from postgres import PostgresCapture, command


def unpack(archive, root):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        require(len(members) <= 100010 and sum(m.size for m in members) <= 1024**3, "archive_size")
        seen = set()
        for member in members:
            name = member.name
            allowed = name in ("manifest.json", "database.dump", "prerequisites.json", "objects") or (
                name.startswith("objects/") and name.count("/") == 1 and name.endswith(".bin"))
            require(allowed and name not in seen and (member.isfile() or member.isdir()), "archive_path")
            require(".." not in name and "\\" not in name, "archive_path")
            seen.add(name)
        tar.extractall(root, members=members, filter="data")
    return verify_bundle(root)


def drill(ciphertext, identity, restore_database=False):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="mn-recovery-") as tmp:
        archive = Path(tmp) / "decrypted.tar"
        command(["age", "--decrypt", "--identity", str(identity), "--output", str(archive), str(ciphertext)])
        root = Path(tmp) / "bundle"
        root.mkdir(mode=0o700)
        manifest = unpack(archive, root)
        if restore_database:
            io = PostgresCapture(None, {})
            try:
                inventory, references, counts = io.restore_and_inspect(
                    (root / "database.dump").read_bytes(), manifest["prerequisites"])
                expected = [{k: obj[k] for k in ("id", "bucket", "key", "version", "size", "etag")} for obj in manifest["objects"]]
                require(inventory == expected and counts == manifest["counts"], "restored_inventory")
                require(all(key in {o['key'] for o in expected} for key in references), "unresolved_reference")
                io.verify_restored_objects(manifest["objects"], root)
            finally:
                io.close_restore()
        return dict(validation="decrypted-and-restored" if restore_database else "decrypted-checksums-only",
                    offsite_origin="operator-must-verify-download",
                    object_count=len(manifest["objects"]))


if __name__ == "__main__":
    try:
        require(len(sys.argv) in (3, 4), "arguments")
        require(len(sys.argv) == 3 or sys.argv[3] == "--restore", "arguments")
        print(json.dumps(drill(sys.argv[1], sys.argv[2], len(sys.argv) == 4)))
    except Exception as error:
        print("recovery: " + (str(error) if isinstance(error, Failure) else "failed"), file=sys.stderr)
        sys.exit(1)
