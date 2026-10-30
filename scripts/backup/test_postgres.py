"""Portable integration: only fixture.sql and disposable local containers."""
import hashlib
import tempfile
import unittest
import uuid
from pathlib import Path
from backup import capture_attempt, Failure, digest
from run import Hosted
from recover import drill
import json
import subprocess
import sys
from postgres import Database, PostgresCapture, prerequisites, start_sandbox, stop_sandbox, command, local_docker, IMAGE, STORAGE_IMAGE, ROLE_SQL, MEMBERS_SQL
from unittest.mock import patch

SYNTHETIC_PROJECT = 'abcdefghijklmnopqrst'


def bootstrap(action, stage):
    """Synthetic-only diagnostics: never print tool stderr, args or environment."""
    try:
        return action()
    except Failure as error:
        known = {'restore_bootstrap': 'database-not-ready',
                 'container_cleanup': 'cleanup-incomplete'}.get(str(error))
        if known:
            raise Failure(f'synthetic-bootstrap:{stage}:{known}:failed') from None
        # command() suppresses traceback chaining, but retains the exception as
        # __context__. Classify it without exposing arbitrary Docker output.
        cause = error.__context__
        status = 'failed'
        category = 'unknown'
        if isinstance(cause, subprocess.CalledProcessError):
            status = 'exit-' + str(cause.returncode)
            message = (cause.stderr or b'').decode(errors='replace').lower()
            for label, patterns in (
                ('daemon-unavailable', ('cannot connect to the docker daemon', 'is the docker daemon running')),
                ('permission-denied', ('permission denied', 'operation not permitted')),
                ('registry-rate-limit', ('toomanyrequests', 'too many requests', 'rate limit')),
                ('image-unavailable', ('manifest unknown', 'no matching manifest', 'not found')),
                ('registry-access', ('unauthorized', 'authentication required', 'pull access denied')),
                ('network', ('tls handshake', 'connection refused', 'connection reset', 'i/o timeout')),
            ):
                if any(pattern in message for pattern in patterns):
                    category = label
                    break
        elif isinstance(cause, subprocess.TimeoutExpired):
            category = 'timeout'
        elif isinstance(cause, OSError):
            category = 'client-unavailable'
        raise Failure(f'synthetic-bootstrap:{stage}:{category}:{status}') from None


def prepare_test_images():
    """Exercise cold image acquisition separately from disconnected DB startup."""
    bootstrap(local_docker, 'local-engine')
    engine = bootstrap(lambda: command(['docker', 'info', '--format', '{{.OSType}}']), 'daemon')
    if engine.strip() != b'linux':
        raise Failure('synthetic-bootstrap:daemon:linux-required:failed')
    for stage, image in (('postgres-pull', IMAGE), ('storage-pull', STORAGE_IMAGE)):
        bootstrap(lambda: command(['docker', 'pull', '--quiet', image]), stage)


class RecoveryTest(unittest.TestCase):
    def test_real_snapshot(self):
        source = bootstrap(start_sandbox, 'postgres-start')
        io = None
        try:
            source.sql(Path(__file__).with_name('fixture.sql').read_text())
            source.sql("CREATE ROLE backup_fixture_observer NOLOGIN; ALTER ROLE backup_fixture_observer SET statement_timeout='1s'; GRANT pg_monitor TO backup_fixture_observer;")
            owner, space, movie, night, asset, obj = [str(uuid.uuid4()) for _ in range(6)]
            version=str(uuid.uuid4())
            data = b"synthetic normalized picture bytes\x00\x01"
            etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
            key = owner + "/" + asset + ".webp"
            source.sql(f"""
              begin;
              insert into storage.buckets(id,name,public) values('profile-avatars','profile-avatars',false);
              insert into auth.users(id,email,encrypted_password,aud,role,email_confirmed_at)
                values('{owner}','synthetic@example.test',extensions.crypt('synthetic-password',extensions.gen_salt('bf')),
                       'authenticated','authenticated',now());
              insert into auth.identities(id,user_id,provider_id,provider,identity_data)
                values('{uuid.uuid4()}','{owner}','{owner}','email','{{"sub":"{owner}"}}');
              insert into public.profiles(id,timezone) values('{owner}','Asia/Jakarta');
              insert into public.movie_spaces(id,name,timezone,created_by) values('{space}','Synthetic','Asia/Jakarta','{owner}');
              insert into public.movie_space_memberships(space_id,user_id,role) values('{space}','{owner}','owner');
              insert into public.movies(id,tmdb_id,title) values('{movie}',2147000001,'Synthetic');
              insert into public.movie_space_watchlist(space_id,movie_id,added_by_user_id) values('{space}','{movie}','{owner}');
              select set_config('request.jwt.claim.sub','{owner}',false);
              insert into public.movie_nights(id,space_id,schedule_mode,scheduled_date) values('{night}','{space}','date_only','2020-01-01');
              insert into public.movie_night_movies values('{night}','{movie}',1);
              insert into public.movie_space_watch_records(space_id,movie_id,watched_precision,created_by_user_id)
                values('{space}','{movie}','unknown','{owner}');
              insert into public.movie_space_movie_ratings values('{space}','{movie}','{owner}',75);
              insert into storage.objects(id,bucket_id,name,version,metadata) values('{obj}','profile-avatars','{key}','{version}',
                '{{"size":{len(data)},"eTag":"{etag}"}}');
              insert into public.profile_avatar_assets(id,user_id,source,object_key,delete_after)
                values('{asset}','{owner}','custom','{key}',null);
              insert into public.profile_avatars(user_id,custom_id) values('{owner}','{asset}');
              commit;
            """)
            source.sql('ALTER ROLE postgres NOSUPERUSER BYPASSRLS;')
            capture_source=Database(source.container,'postgres')
            pre = prerequisites(capture_source)
            io = PostgresCapture(capture_source, dict(project=SYNTHETIC_PROJECT, schema_sha256=pre["schema_sha256"],
                source_version=pre["server_version"], max_database_bytes=500*1024*1024,
                prerequisites_sha256=digest(json.dumps(pre,sort_keys=True,separators=(',',':')).encode())))
            io.object_bytes = lambda item: (data, etag, etag)
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'capture';root.mkdir()
                manifest = capture_attempt(io, root)
                self.assertEqual(len(manifest["objects"]), 1)
                self.assertEqual(manifest["counts"]["auth.users"], 1)
                self.assertEqual(manifest["counts"]["auth.identities"], 1)
                self.assertEqual(manifest["counts"]["public.movie_space_movie_ratings"], 1)
                self.assertEqual(io.restored.sql("select encrypted_password=extensions.crypt('synthetic-password',encrypted_password) from auth.users;"), 't')
                self.assertEqual(io.restored.json(ROLE_SQL),pre['roles'])
                self.assertEqual(io.restored.json(MEMBERS_SQL),pre['memberships'])
                self.assertEqual(io.restored.sql("select encode(extensions.digest('synthetic','sha256'),'hex');"),digest(b'synthetic'))
                # Source survives and restored permissions still deny direct reads.
                self.assertEqual(source.sql("select count(*) from public.movie_spaces;"), "1")
                self.assertEqual(io.restored.sql("set role anon; select count(*) from public.profile_avatar_assets;"), '0')
                self.assertEqual(io.restored.sql("set role authenticated; select count(*) from public.movie_space_movie_ratings;"), '0')
                self.assertEqual(io.restored.sql(f"set role authenticated; select set_config('request.jwt.claim.sub','{owner}',false); select count(*) from public.list_movie_space_movie_ratings('{space}');").splitlines()[-1], '1')
                identity=Path(tmp)/'synthetic-identity'
                command(['age-keygen','--output',str(identity)])
                io.recipient=command(['age-keygen','-y',str(identity)]).decode().strip()
                io.work=Path(tmp)
                encrypted=Hosted.encrypt(io,root,Path(tmp)/'bundle.tar.age')
                with patch('backup.PROJECT_SHA256', digest(SYNTHETIC_PROJECT.encode())):
                    self.assertEqual(drill(encrypted,identity,True)['validation'],'decrypted-and-restored')
                # Capture inventory is from the archive: deleting a source object
                # AFTER pg_dump cannot make it disappear from the restored list.
                original_dump = io.dump
                def dump_then_remove():
                    result = original_dump()
                    source.sql("update storage.objects set name='changed-after-snapshot';")
                    return result
                io.close_restore()
                io.dump = dump_then_remove
                io.object_bytes = lambda item: (_ for _ in ()).throw(Failure("object_missing"))
                with tempfile.TemporaryDirectory() as missing:
                    with self.assertRaisesRegex(Failure, "object_missing"):
                        capture_attempt(io, missing)
        finally:
            if io:
                io.close_restore()
            stop_sandbox(source)


if __name__ == "__main__":
    try:
        prepare_test_images()
    except Failure as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    unittest.main()
