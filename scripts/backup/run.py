"""Approved hosted entry point. Credentials are never accepted on command lines."""
import json
import os
import re
import signal
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from backup import REPOSITORY, REPOSITORY_ID, Failure, digest, policy_guard, require, run_backup
from postgres import IMAGE, Database, PostgresCapture, command, local_docker, base_env, remove_container


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get(url, headers=None, limit=262145):
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = response.read(limit)
            require(len(data) < limit, "http_size")
            return data
    except (OSError, urllib.error.HTTPError):
        raise Failure("http_failed") from None


def etag(value):
    return str(value).strip('"').lower()


def signal_healthcheck(success):
    url = os.environ["BACKUP_HEALTHCHECK_URL"]
    require(re.fullmatch(r"https://hc-ping\.com/[0-9a-f-]{36}", url), "monitor")
    get(url + ("" if success else "/fail"), limit=65536)


def github_read():
    headers={'User-Agent':'movie-night-backup'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization']='Bearer '+os.environ['GITHUB_TOKEN']
    # Only this public repository's metadata, never private issues or contents.
    return json.loads(get('https://api.github.com/repos/'+REPOSITORY,headers,limit=1048576))


def approved_policy(raw, expected_hash):
    policy = json.loads(raw)
    require(re.fullmatch(r'[0-9a-f]{64}', expected_hash or ''), 'setup_review')
    actual = digest(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode())
    require(actual == expected_hash, 'setup_review')
    return policy


def drive_client_credentials():
    values = tuple(os.environ.get(key, '') for key in
                   ('BACKUP_DRIVE_CLIENT_ID', 'BACKUP_DRIVE_CLIENT_SECRET'))
    require(all(value.strip() for value in values), 'drive_client')
    return values


class Hosted(PostgresCapture):
    def __init__(self, source, policy, work, recipient):
        client_id, client_secret = drive_client_credentials()
        super().__init__(source, policy)
        self.work, self.recipient = Path(work), recipient
        self.headers = {"apikey": os.environ["BACKUP_STORAGE_KEY"],
                        "Authorization": "Bearer " + os.environ["BACKUP_STORAGE_KEY"]}
        self.root = "https://" + policy['project'] + ".supabase.co/storage/v1"
        self.remote_env = dict(base_env(), RCLONE_CONFIG_MN_TYPE="drive",
                               RCLONE_CONFIG_MN_SCOPE="drive.file",
                               RCLONE_CONFIG_MN_CLIENT_ID=client_id,
                               RCLONE_CONFIG_MN_CLIENT_SECRET=client_secret,
                               RCLONE_CONFIG_MN_ROOT_FOLDER_ID=policy["drive_folder"],
                               RCLONE_CONFIG_MN_TOKEN=os.environ["BACKUP_DRIVE_TOKEN"])
        # Pinned rclone OAuth overrides take the plain client secret, not obscure.
        # No inherited user config/remotes: only the pinned folder is reachable.
        self.config = self.work / "rclone.conf"
        self.config.write_text("", encoding="utf8")
        self.config.chmod(0o600)
        token=json.loads(os.environ['BACKUP_DRIVE_TOKEN'])
        require(isinstance(token.get('refresh_token'),str) and bool(token['refresh_token']), 'drive_token')
        bucket=json.loads(get(self.root+'/bucket/profile-avatars',self.headers))
        require(bucket.get('id')=='profile-avatars' and bucket.get('public') is False, 'bucket')
        # Root StatJSON is a synthetic directory without an ID in pinned rclone.
        # Drive's read-only query returns real File metadata instead. Restrict
        # the query to the approved folder name/type; bind its actual ID below.
        folder_name='Movie Night production backups'
        folder_type='application/vnd.google-apps.folder'
        query=f"name = '{folder_name}' and mimeType = '{folder_type}' and trashed = false"
        folders=json.loads(self.rclone(['backend','query','mn:',query]))
        require(isinstance(folders,list), 'drive_folder')
        matches=[folder for folder in folders if isinstance(folder,dict)
                 and folder.get('id')==policy['drive_folder'] and folder.get('name')==folder_name
                 and folder.get('mimeType')==folder_type and folder.get('trashed',False) is False]
        require(len(matches)==1, 'drive_folder')
        self.capacity(policy['max_bundle_bytes'])

    def rclone(self, args):
        return command(["rclone", "--config", str(self.config), "--retries", "1",
                        "--low-level-retries", "1", *args], env=self.remote_env)

    def object_bytes(self, item):
        path = urllib.parse.quote(item["bucket"] + "/" + item["key"], safe="/")
        def info():
            meta = json.loads(get(self.root + "/object/info/authenticated/" + path, self.headers))
            require(meta.get("id") == item["id"] and meta.get('name') == item['key']
                    and meta.get('bucket_id') == item['bucket'] and meta.get('size') == item['size']
                    and 'version' in meta and meta['version'] == item['version'], "object_identity")
            return etag(meta.get("etag", ""))
        before = info()
        data = get(self.root + "/object/" + path, self.headers)
        return data, before, info()

    def encrypt(self, root, output):
        size=sum(path.stat().st_size + 1024 for path in Path(root).rglob('*') if path.is_file())
        require(size + 65536 <= getattr(self,'policy',{}).get('max_bundle_bytes',512*1024*1024), 'bundle_capacity')
        archive = self.work / "bundle.tar"
        with tarfile.open(archive, "w") as tar:
            for path in sorted(Path(root).rglob("*")):
                require(not path.is_symlink(), "archive_path")
                tar.add(path, arcname=path.relative_to(root), recursive=False)
        command(["age", "--recipient", self.recipient, "--output", str(output), str(archive)])
        return output

    def upload(self, file, name):
        self.capacity(Path(file).stat().st_size)
        require(Path(file).stat().st_size <= self.policy["max_bundle_bytes"], "bundle_capacity")
        self.rclone(["copyto", "--immutable", str(file), "mn:" + name])

    def capacity(self, size):
        capacity = json.loads(self.rclone(["about", "mn:", "--json"]))
        require(isinstance(capacity.get("free"), int) and capacity["free"] > size,
                "drive_capacity")

    def readback_hash(self, name):
        # rclone does not guarantee a Drive SHA256; hash downloaded ciphertext.
        file = self.work / "readback.age"
        self.rclone(["copyto", "--immutable", "mn:" + name, str(file)])
        return digest(file.read_bytes())

    def signal(self, success):
        signal_healthcheck(success)


def main():
    source_name = None
    io = None
    try:
        require('REPLACE_' not in REPOSITORY and REPOSITORY != 'Finn84FIN/movie-night'
                and re.fullmatch(r'[1-9][0-9]*', REPOSITORY_ID), 'unconfigured')
        require(os.environ['GITHUB_REPOSITORY'] == REPOSITORY
                and os.environ['GITHUB_REPOSITORY_ID'] == REPOSITORY_ID, 'repository_identity')
        drive_client_credentials()  # Fail before provider reads or snapshot setup.
        # Read the GitHub event AND independently verify public API visibility.
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        require(event.get("repository", {}).get("private") is False, "visibility")
        public = github_read()
        require(public.get("private") is False and public.get("full_name") == REPOSITORY
                and str(public.get('id')) == REPOSITORY_ID
                and public.get('default_branch') == 'main'
                and str(event['repository'].get('id')) == REPOSITORY_ID, "visibility")
        policy = approved_policy(os.environ['BACKUP_POLICY_JSON'], os.environ.get('BACKUP_POLICY_SHA256'))
        context = dict(repository=os.environ["GITHUB_REPOSITORY"], visibility="public",
                       repository_id=os.environ['GITHUB_REPOSITORY_ID'],
                       event=os.environ["GITHUB_EVENT_NAME"], ref=os.environ["GITHUB_REF"],
                       runner=os.environ["BACKUP_RUNNER"], code_sha=os.environ["BACKUP_CODE_SHA"])
        context.update(environment=os.environ.get('RUNNER_ENVIRONMENT'),os=os.environ.get('RUNNER_OS'),
                       arch=os.environ.get('RUNNER_ARCH'),actor=os.environ.get('GITHUB_ACTOR'))
        recipient = os.environ["BACKUP_RECIPIENT"]
        policy_guard(policy, context, recipient)
        require(re.fullmatch(r'https://hc-ping\.com/[0-9a-f-]{36}',os.environ['BACKUP_HEALTHCHECK_URL']), 'monitor')
        require(0 < policy["max_bundle_bytes"] <= 512 * 1024 * 1024, "capacity")
        require(re.fullmatch(r"aws-\d+-[a-z0-9-]+\.pooler\.supabase\.com", policy["pooler_host"]), "database_host")
        require(policy.get("database_user") == "postgres." + policy['project'], "database_user")
        # Validate age's recipient checksum before capturing any private data.
        command(['age','--recipient',recipient], b'')
        # Fixed project host/user and verify-full TLS bind the session pooler to
        # this project. Never accept arbitrary DATABASE_URLs/SSL downgrade flags.
        pg_env = dict(base_env(), PGHOST=policy["pooler_host"], PGPORT="5432", PGDATABASE="postgres",
                      PGUSER=policy["database_user"], PGPASSWORD=os.environ["BACKUP_DB_PASSWORD"],
                      PGSSLMODE="verify-full", PGSSLROOTCERT="system")
        local_docker()
        source_name = "mn-backup-client-" + os.urandom(12).hex()
        command(["docker", "run", "--detach", "--name", source_name, "--network", "bridge",
                 "--entrypoint", "sleep", IMAGE, "infinity"])
        source = Database(source_name, source_env=pg_env)
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="mn-backup-", dir=os.environ.get("RUNNER_TEMP")) as work:
            require(shutil.disk_usage(work).free > policy['max_bundle_bytes'] * 6, 'disk_capacity')
            io = Hosted(source, policy, work, recipient)
            result = run_backup(io, work)
        remove_container(source_name)
        source_name = None
        io.signal(True)
        # Aggregate status only. Never expose manifest or tool exception text.
        print(json.dumps(result))
    except Exception as error:
        if io:
            try:
                io.signal(False)
            except Exception:
                pass
        else:
            try:
                signal_healthcheck(False)
            except Exception:
                pass
        print("backup: " + (str(error) if isinstance(error, Failure) else "failed"), file=sys.stderr)
        return 1
    finally:
        if source_name:
            try:
                remove_container(source_name)
            except Failure:
                print("backup: client_cleanup_failed", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
