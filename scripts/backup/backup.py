"""Movie Night backup primitives. Only the reviewed runner may supply live adapters.

No dependency on the app, dotenv, or provider SDKs. Never print caught exceptions:
they may contain database credentials, object paths or Auth records.
"""
import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from target import REPOSITORY, REPOSITORY_ID, PROJECT_SHA256, DRIVE_ACCOUNT_SHA256

IMAGE = "public.ecr.aws/supabase/postgres@sha256:28f0e16a019e648089fc1a6d333549a55548f6019c15ae4bd7cd58b989027518"


class Failure(Exception):
    """A public, content-free stage code. Never attach provider exception text."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def policy_guard(policy, context, recipient):
    require(re.fullmatch(r"Finn84FIN/[A-Za-z0-9_.-]+", REPOSITORY)
            and 'REPLACE_' not in REPOSITORY and REPOSITORY != 'Finn84FIN/movie-night', "unconfigured")
    require(re.fullmatch(r'[1-9][0-9]*', REPOSITORY_ID), 'unconfigured')
    require(context.get("repository") == REPOSITORY, "repository")
    require(str(context.get('repository_id')) == REPOSITORY_ID
            and policy.get('repository') == REPOSITORY
            and str(policy.get('repository_id')) == REPOSITORY_ID, 'repository_identity')
    require(context.get("visibility") == "public", "visibility")
    require(context.get("event") in ("schedule", "workflow_dispatch"), "event")
    require(context.get("ref") == "refs/heads/main", "ref")
    require(context.get("runner") == "ubuntu-24.04", "runner")
    require(context.get('environment')=='github-hosted' and context.get('os')=='Linux'
            and context.get('arch')=='X64', 'runner')
    require(context.get('actor')=='Finn84FIN', 'actor')
    require(policy.get("enabled") is True, "disabled")
    require(isinstance(policy.get('project'), str) and re.fullmatch(r'[a-z]{20}', policy['project'])
            and digest(policy['project'].encode()) == PROJECT_SHA256, "project")
    require(re.fullmatch(r"[0-9a-f]{40}", policy.get("code_sha", "")), "revision")
    require(policy["code_sha"] == context.get("code_sha"), "revision")
    try:
        expires = datetime.fromisoformat(policy["expires"].replace("Z", "+00:00"))
        require(datetime.now(timezone.utc) < expires <= datetime.now(timezone.utc) + timedelta(days=31), "expired")
    except (KeyError, ValueError, TypeError):
        raise Failure("expired") from None
    require(policy.get("recipient_sha256") == digest(recipient.encode()), "recipient")
    require(re.fullmatch(r"age1[0-9a-z]{58}", recipient), "recipient")
    require(isinstance(policy.get('drive_account'), str)
            and digest(policy['drive_account'].encode()) == DRIVE_ACCOUNT_SHA256, "drive")
    require(re.fullmatch(r"[A-Za-z0-9_-]{10,200}", policy.get("drive_folder", "")), "drive")
    # This is an expiring, reviewed setup receipt, NOT a live billing API claim.
    # The provider plans cannot be upgraded by this job. Independent setup must
    # establish that these services stop rather than bill when free limits end.
    require(re.fullmatch(r"https://github.com/Finn84FIN/movie-night/issues/[1-9][0-9]*",
                         policy.get("setup_review_url", "")), "setup_review")
    require(policy.get("provider_free_blocks_verified") is True, "cost_unverified")
    require(policy.get("free_capacity_verified") is True, "capacity_unverified")
    require(re.fullmatch(r"17[0-9]{4}", policy.get("source_version", "")) and
            re.fullmatch(r"[0-9a-f]{64}", policy.get("schema_sha256", "")) and
            re.fullmatch(r"[0-9a-f]{64}", policy.get("prerequisites_sha256", "")), "schema")
    if 'source_application' in policy:
        app=policy['source_application']
        require(isinstance(app,dict) and set(app)=={'commit','version','verification','evidence_url'}, 'application_metadata')
        require(re.fullmatch(r'[0-9a-f]{40}',app['commit']) and
                re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',app['version']) and app['verification']=='setup-recorded'
                and re.fullmatch(r'https://github.com/Finn84FIN/movie-night/issues/[1-9][0-9]*',app['evidence_url']), 'application_metadata')


def safe_object(item):
    require(item.get("bucket") == "profile-avatars", "bucket")
    key = item.get("key", "")
    require(isinstance(key, str) and len(key) < 1024, "object_path")
    require(all(p not in ("", ".", "..") for p in key.split("/"))
            and "\\" not in key and not any(ord(c) < 32 for c in key), "object_path")
    try:
        require(str(uuid.UUID(item["id"])) == item["id"], 'object_id')
        if item.get('version') is not None:
            require(str(uuid.UUID(item['version'])) == item['version'], 'object_version')
    except (ValueError, KeyError, TypeError):
        raise Failure("object_id") from None
    require(isinstance(item.get("size"), int) and 0 <= item["size"] <= 262144, "object_size")
    require(isinstance(item.get("etag"), str) and re.fullmatch(r"[0-9a-fA-F]{32}", item["etag"]), "object_identity")


def capture_attempt(io, root):
    """Inventory MUST come from the restored archive, never the live source."""
    root = Path(root)
    started = now()
    archive, prerequisites = io.dump()
    require(archive.startswith(b"PGDMP"), "dump")
    (root / "database.dump").write_bytes(archive)
    (root / "prerequisites.json").write_text(json.dumps(prerequisites), encoding="utf8")
    inventory, references, counts = io.restore_and_inspect(archive, prerequisites)
    require(len(inventory) <= 100000, "inventory")
    for item in inventory:
        safe_object(item)
    require(sum(item['size'] for item in inventory) <= 256 * 1024 * 1024, "object_capacity")
    ids, keys = set(), set()
    objects = []
    (root / "objects").mkdir()
    for item in inventory:
        safe_object(item)
        require(item["id"] not in ids and item["key"] not in keys, "duplicate_object")
        ids.add(item["id"])
        keys.add(item["key"])
        data, before, after = io.object_bytes(item)
        require(len(data) == item["size"], "object_size")
        # Compare to the fingerprint IN THE SNAPSHOT, not only a later HEAD.
        require(hashlib.md5(data, usedforsecurity=False).hexdigest().lower()
                == item["etag"].lower(), "object_changed")
        require(before == after == item["etag"].lower(), "object_changed")
        name = item["id"] + ".bin"
        (root / "objects" / name).write_bytes(data)
        objects.append(dict(item, file="objects/" + name, sha256=digest(data)))
    require(all(key in keys for key in references), "unresolved_reference")
    # A second independent read checks what will actually be bundled.
    for obj in objects:
        require(digest((root / obj["file"]).read_bytes()) == obj["sha256"], "object_corrupt")
    io.verify_restored_objects(objects, root)
    manifest = dict(format=1, project=io.policy['project'], started=started, finished=now(),
                    dump_sha256=digest(archive), objects=objects, counts=counts,
                    validation="snapshot-restored", recovery_drill="not-performed",
                    prerequisites=prerequisites)
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf8")
    return manifest


def run_backup(io, workspace):
    """Two captures maximum; NEVER retry upload or report capture success early."""
    generation = "mn-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + str(uuid.uuid4())
    manifest = None
    try:
        for attempt in range(2):
            root = Path(workspace) / ("capture-" + str(attempt))
            root.mkdir(mode=0o700)
            try:
                manifest = capture_attempt(io, root)
                manifest['generation'] = generation
                manifest['tool_revision'] = getattr(io,'policy',{}).get('code_sha','not-observed')
                manifest['source_application'] = getattr(io,'policy',{}).get('source_application',{'verification':'not-observed'})
                (root/'manifest.json').write_text(json.dumps(manifest,sort_keys=True),encoding='utf8')
                break
            except Failure:
                if attempt:
                    raise
            finally:
                # Even failed database restores must release their sandbox.
                io.close_restore()
            shutil.rmtree(root)
        encrypted = io.encrypt(root, Path(workspace) / (generation + ".tar.age"))
        require(Path(encrypted).is_file() and Path(encrypted).stat().st_size > 0, "encrypt")
        checksum = digest(Path(encrypted).read_bytes())
        io.upload(encrypted, generation + ".tar.age")
        require(io.readback_hash(generation + ".tar.age") == checksum, "readback")
        result = dict(generation=generation, validation="snapshot-restored",
                    encrypted_readback="passed", recovery_drill="not-performed",
                    ciphertext_sha256=checksum,
                    object_count=len(manifest["objects"]))
    finally:
        io.close_restore()
    # Success is emitted by the caller only after workspace/client cleanup.
    return result


def verify_bundle(root):
    """Offline verification after age decryption; never executes dump contents."""
    root = Path(root)
    for filename in ("manifest.json", "database.dump", "prerequisites.json"):
        require(not (root / filename).is_symlink() and (root / filename).is_file(), "archive_path")
    m = json.loads((root / "manifest.json").read_text(encoding="utf8"))
    require(m["format"] == 1 and isinstance(m.get('project'), str)
            and digest(m['project'].encode()) == PROJECT_SHA256, "manifest")
    require(digest((root / "database.dump").read_bytes()) == m["dump_sha256"], "dump_corrupt")
    require(json.loads((root / 'prerequisites.json').read_text(encoding='utf8')) == m['prerequisites'], 'prerequisites')
    seen = set()
    for obj in m["objects"]:
        safe_object(obj)
        expected = "objects/" + obj["id"] + ".bin"
        require(obj["file"] == expected and expected not in seen, "object_path")
        seen.add(expected)
        path = root / expected
        require(not path.is_symlink() and path.is_file(), "object_path")
        data = path.read_bytes()
        require(len(data) == obj["size"] and digest(data) == obj["sha256"], "object_corrupt")
    return m
