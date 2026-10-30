import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr
from backup import Failure, digest, policy_guard, run_backup, verify_bundle
from postgres import command, normalized_schema, start_sandbox
from run import Hosted, main, approved_policy
from recover import drill, unpack
from test_postgres import bootstrap, prepare_test_images
import target

DATA = b'synthetic picture bytes'
ETAG = hashlib.md5(DATA, usedforsecurity=False).hexdigest()
ITEM = dict(id=str(uuid.uuid4()), bucket='profile-avatars', key='owner/picture.webp', version=None, size=len(DATA), etag=ETAG)
PROJECT = 'abcdefghijklmnopqrst'
REPOSITORY = 'Finn84FIN/synthetic-backup-tests'
REPOSITORY_ID = '999228'


class Fixture:
    def __init__(self, work, recipient):
        self.work, self.recipient = Path(work), recipient
        self.policy = {'project': PROJECT}
        self.calls, self.signals, self.remote = [], [], {}
        self.fail = ''
        self.captures = 0
    def dump(self):
        self.calls.append('dump')
        self.captures += 1
        return b'PGDMPsynthetic', {'fixture': True}
    def restore_and_inspect(self, archive, pre):
        self.calls.append('restore')
        return [ITEM], [ITEM['key']], {'auth.users': 1}
    def object_bytes(self, item):
        self.calls.append('object')
        if self.fail == 'missing':
            raise Failure('object_missing')
        return DATA, ETAG, ('0'*32 if self.fail == 'changed' else ETAG)
    def verify_restored_objects(self, objects, root):
        self.calls.append('verify')
    def close_restore(self):
        self.calls.append('close')
        if self.fail == 'cleanup':
            raise Failure('cleanup')
    encrypt = Hosted.encrypt
    def upload(self, file, name):
        self.calls.append('upload')
        if self.fail == 'upload':
            raise Failure('upload')
        if name in self.remote:
            raise Failure('overwrite')
        self.remote[name] = Path(file).read_bytes()
    def readback_hash(self, name):
        self.calls.append('readback')
        return digest(self.remote[name] + (b'x' if self.fail == 'readback' else b''))
    def signal(self, ok):
        self.signals.append(ok)


class BackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.identity = Path(cls.keys.name) / 'synthetic-key'
        command(['age-keygen', '--output', str(cls.identity)])
        cls.recipient = command(['age-keygen', '-y', str(cls.identity)]).decode().strip()
    def setUp(self):
        credentials=patch.dict(os.environ, BACKUP_DRIVE_CLIENT_ID='synthetic-client-id',
                               BACKUP_DRIVE_CLIENT_SECRET='synthetic-client-secret')
        credentials.start();self.addCleanup(credentials.stop)
        # Synthetic bindings live only in test memory. target.py stays inert.
        for module in ('backup', 'run'):
            for key, value in [('REPOSITORY', REPOSITORY), ('REPOSITORY_ID', REPOSITORY_ID)]:
                p=patch(module+'.'+key,value);p.start();self.addCleanup(p.stop)
        for key, value in [('PROJECT_SHA256',digest(PROJECT.encode())),
                           ('DRIVE_ACCOUNT_SHA256',digest(b'synthetic@example.test'))]:
            p=patch('backup.'+key,value);p.start();self.addCleanup(p.stop)
    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()
    def policy(self):
        return dict(enabled=True, project=PROJECT, repository=REPOSITORY, repository_id=REPOSITORY_ID, code_sha='a'*40,
            expires=(datetime.now(timezone.utc)+timedelta(days=7)).isoformat(),
            recipient_sha256=digest(self.recipient.encode()), drive_account='synthetic@example.test',
            drive_folder='synthetic-folder', setup_review_url='https://github.com/Finn84FIN/movie-night/issues/999',
            provider_free_blocks_verified=True, free_capacity_verified=True,
            source_version='170011', schema_sha256='a'*64, prerequisites_sha256='a'*64,
            pooler_host='aws-0-example.pooler.supabase.com', database_user='postgres.'+PROJECT,
            max_database_bytes=500*1024*1024,max_bundle_bytes=512*1024*1024)
    def context(self):
        return dict(repository=REPOSITORY, repository_id=REPOSITORY_ID, visibility='public', event='schedule', ref='refs/heads/main',
                    runner='ubuntu-24.04', code_sha='a'*40, environment='github-hosted',os='Linux',arch='X64',actor='Finn84FIN')
    def test_policy(self):
        policy_guard(self.policy(), self.context(), self.recipient)
        cases = [('enabled',False),('provider_free_blocks_verified',False),('free_capacity_verified',False),
                 ('project','wrong'),('code_sha','main'),('source_version','160001'),
                 ('expires','2000-01-01T00:00:00Z'),('recipient_sha256','wrong')]
        for key, value in cases:
            with self.subTest(key=key), self.assertRaises(Failure):
                policy_guard(dict(self.policy(), **{key:value}), self.context(), self.recipient)
        for key, value in [('event','pull_request'),('event','push'),('ref','refs/heads/dev'),
                           ('visibility','private'),('runner','paid'),('repository','elsewhere'),
                           ('environment','self-hosted'),('actor','unknown'),('repository_id','123')]:
            with self.subTest(key=key), self.assertRaises(Failure):
                policy_guard(self.policy(), dict(self.context(), **{key:value}), self.recipient)
    def test_schema_fingerprint_preserves_function_string_contents(self):
        def dump(key,version,body):
            return b'-- PostgreSQL database dump\n\\restrict '+key+b'\n-- Dumped from database version '+version+b'\nSET statement_timeout = 0;\n'+body+b'\n\\unrestrict '+key+b'\n'
        body=b"CREATE FUNCTION f() RETURNS text AS $$begin\r\nreturn 'a\n--meaningful\n\\restrict inside';end$$ LANGUAGE plpgsql;"
        a=normalized_schema(dump(b'abc',b'17.6',body))
        self.assertEqual(a,normalized_schema(dump(b'def',b'17.11',body)))
        self.assertIn(b'\r\n',a)
        self.assertNotEqual(a,normalized_schema(dump(b'def',b'17.11',body.replace(b'--meaningful',b'--changed'))))
    def test_synthetic_bootstrap_classifies_without_exposing_tool_output(self):
        for message,category in (
            ('Cannot connect to the Docker daemon','daemon-unavailable'),
            ('operation not permitted','permission-denied'),
            ('toomanyrequests','registry-rate-limit'),
            ('manifest unknown','image-unavailable'),
            ('pull access denied','registry-access'),
            ('TLS handshake timeout','network'),
            ('unrecognized failure','unknown'),
        ):
            private='PRIVATE password SQL object-path provider-url'
            failure=subprocess.CalledProcessError(125,['docker','PRIVATE'],stderr=(message+' '+private).encode())
            with self.subTest(category=category),patch('postgres.subprocess.run',side_effect=failure):
                with self.assertRaisesRegex(Failure,f'^synthetic-bootstrap:postgres-start:{category}:exit-125$') as caught:
                    bootstrap(lambda:command(['docker','run']), 'postgres-start')
                self.assertNotIn(private,str(caught.exception))
                # The production wrapper's error surface is unchanged.
                with self.assertRaisesRegex(Failure,'^tool_failed$'):command(['docker','run'])
        for failure,category in ((subprocess.TimeoutExpired(['docker'],300),'timeout'),
                                 (FileNotFoundError('PRIVATE-client-path'),'client-unavailable')):
            with patch('postgres.subprocess.run',side_effect=failure), \
                 self.assertRaisesRegex(Failure,f'^synthetic-bootstrap:daemon:{category}:failed$'):
                bootstrap(lambda:command(['docker','info']), 'daemon')
    def test_cold_recovery_preflight_uses_only_local_engine_and_fixed_images(self):
        from postgres import IMAGE, STORAGE_IMAGE
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            self.assertFalse(any(k.startswith(('BACKUP_','RCLONE_')) for k in kwargs['env']))
            output=b'linux\n' if args[1]=='info' else b''
            return subprocess.CompletedProcess(args,0,stdout=output,stderr=b'')
        with patch('test_postgres.local_docker') as local,patch('postgres.subprocess.run',side_effect=run):
            prepare_test_images()
            local.assert_called_once_with()
        self.assertEqual(calls,[['docker','info','--format','{{.OSType}}'],
                               ['docker','pull','--quiet',IMAGE],['docker','pull','--quiet',STORAGE_IMAGE]])
        with patch('test_postgres.local_docker'),patch('postgres.subprocess.run',
                return_value=subprocess.CompletedProcess([],0,stdout=b'windows\n')) as process, \
             self.assertRaisesRegex(Failure,'^synthetic-bootstrap:daemon:linux-required:failed$'):
            prepare_test_images()
        self.assertEqual(process.call_count,1)
        def unavailable(args,**kwargs):
            if args[1]=='pull':raise subprocess.CalledProcessError(125,args,stderr=b'manifest unknown PRIVATE')
            return subprocess.CompletedProcess(args,0,stdout=b'linux\n')
        with patch('test_postgres.local_docker'),patch('postgres.subprocess.run',side_effect=unavailable) as process, \
             self.assertRaisesRegex(Failure,'^synthetic-bootstrap:postgres-pull:image-unavailable:exit-125$'):
            prepare_test_images()
        self.assertEqual(process.call_count,2)
    def test_known_readiness_and_cleanup_failures_keep_safe_classifications(self):
        for code,category in (('restore_bootstrap','database-not-ready'),
                              ('container_cleanup','cleanup-incomplete')):
            for with_context in (False,True):
                def fail():
                    if with_context:
                        try:
                            raise subprocess.CalledProcessError(125,['PRIVATE'],stderr=b'permission denied PRIVATE')
                        except subprocess.CalledProcessError:
                            raise Failure(code) from None
                    raise Failure(code)
                with self.subTest(code=code,with_context=with_context), \
                     self.assertRaisesRegex(Failure,f'^synthetic-bootstrap:postgres-start:{category}:failed$'):
                    bootstrap(fail,'postgres-start')
        for private in ('PRIVATE password SQL object-path',
                        'restore_bootstrap PRIVATE','container_cleanup PRIVATE'):
            def fail():raise Failure(private)
            with self.subTest(private=private), \
                 self.assertRaisesRegex(Failure,'^synthetic-bootstrap:postgres-start:unknown:failed$') as caught:
                bootstrap(fail,'postgres-start')
            self.assertNotIn(private,str(caught.exception))
    def test_restore_readiness_waits_for_final_listener_and_cleans_timeout(self):
        with patch('postgres.local_docker'),patch('postgres.command',return_value=b'synthetic'), \
             patch('postgres.Database') as database,patch('postgres.time.sleep') as sleep, \
             patch('postgres.remove_container') as cleanup:
            db=database.return_value
            db.run.side_effect=[Failure('tool_failed'),b'accepting connections']
            db.sql.return_value='1'
            self.assertIs(start_sandbox(),db)
            expected=('pg_isready',['-h','127.0.0.1','-p','5432','-t','1'])
            self.assertEqual([call.args for call in db.run.call_args_list],[expected,expected])
            db.sql.assert_called_once_with('select 1;')
            sleep.assert_called_once_with(1)
            cleanup.assert_not_called()
            db.run.reset_mock();db.sql.reset_mock();sleep.reset_mock()
            db.run.side_effect=Failure('tool_failed')
            with self.assertRaisesRegex(Failure,'^restore_bootstrap$'):start_sandbox()
            self.assertEqual(db.run.call_count,60)
            db.sql.assert_not_called()
            cleanup.assert_called_once()
            self.assertTrue(cleanup.call_args.args[0].startswith('mn-backup-restore-'))
    def test_encrypted_capture_and_offline_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(tmp,self.recipient)
            fixture.remote['last-good'] = b'unchanged'
            result = run_backup(fixture,tmp)
            self.assertEqual(fixture.remote['last-good'], b'unchanged')
            self.assertEqual(result['recovery_drill'],'not-performed')
            self.assertEqual(fixture.signals, []) # caller waits for cleanup
            ciphertext = Path(tmp)/(result['generation']+'.tar.age')
            self.assertNotIn(DATA, ciphertext.read_bytes())
            self.assertEqual(drill(ciphertext,self.identity)['validation'],'decrypted-checksums-only')
            corrupted = Path(tmp)/'corrupt.age'
            data = bytearray(ciphertext.read_bytes()); data[-1] ^= 1
            corrupted.write_bytes(data)
            with self.assertRaises(Failure): drill(corrupted,self.identity)
            root = Path(tmp)/'capture-0'
            original=(root/'database.dump').read_bytes()
            (root/'database.dump').write_bytes(b'corrupt')
            with self.assertRaisesRegex(Failure,'dump_corrupt'): verify_bundle(root)
            (root/'database.dump').write_bytes(original)
            (root/'objects'/(ITEM['id']+'.bin')).write_bytes(b'corrupt')
            with self.assertRaisesRegex(Failure,'object_corrupt'): verify_bundle(root)
    def test_failures_no_success_and_bounded_retry(self):
        for failure in ('missing','changed','upload','readback','cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture=Fixture(tmp,self.recipient); fixture.fail=failure
                with self.assertRaises(Failure): run_backup(fixture,tmp)
                self.assertNotIn(True,fixture.signals)
                self.assertLessEqual(fixture.captures,2)
                if failure in ('missing','changed'): self.assertEqual(fixture.captures,2)
    def test_archive_path_rejection(self):
        for name, kind in [('../escape',tarfile.REGTYPE),('objects/evil.bin',tarfile.SYMTYPE),
                           ('manifest.json',tarfile.LNKTYPE)]:
            with tempfile.TemporaryDirectory() as tmp:
                archive=Path(tmp)/'bad.tar'
                with tarfile.open(archive,'w') as tar:
                    member=tarfile.TarInfo(name);member.type=kind;member.linkname='/escape';tar.addfile(member)
                with self.assertRaises(Failure): unpack(archive,Path(tmp)/'out')
    def test_hosted_entry_cleanup_before_success_and_sanitized_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            event=Path(tmp)/'event.json';event.write_text(json.dumps({'repository':{'private':False,'id':int(REPOSITORY_ID)}}))
            policy=self.policy()
            env=dict(GITHUB_EVENT_PATH=str(event),GITHUB_REPOSITORY=REPOSITORY,GITHUB_REPOSITORY_ID=REPOSITORY_ID,GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_REF='refs/heads/main',BACKUP_RUNNER='ubuntu-24.04',BACKUP_CODE_SHA='a'*40,
                RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Linux',RUNNER_ARCH='X64',GITHUB_ACTOR='Finn84FIN',
                BACKUP_RECIPIENT=self.recipient,BACKUP_POLICY_JSON=json.dumps(policy),BACKUP_DB_PASSWORD='PRIVATE-TEST-PASSWORD')
            env['BACKUP_POLICY_SHA256']=digest(json.dumps(policy,sort_keys=True,separators=(',',':')).encode())
            env['BACKUP_HEALTHCHECK_URL']='https://hc-ping.com/00000000-0000-0000-0000-000000000000'
            fixture_ref=[]; commands=[]
            def factory(source, policy, work, recipient):
                f=Fixture(work,recipient)
                def signal(ok):
                    if ok:
                        self.assertFalse(Path(work).exists())
                        self.assertTrue(any('rm' in c for c in commands))
                    f.signals.append(ok)
                f.signal=signal;fixture_ref.append(f);return f
            def get(url,*args,**kwargs):
                self.assertEqual(url,'https://api.github.com/repos/'+REPOSITORY)
                return json.dumps({'private':False,'full_name':REPOSITORY,'id':int(REPOSITORY_ID),'default_branch':'main'}).encode()
            output=io.StringIO()
            def mock_command(args,data=None):
                if args[0]=='docker':
                    commands.append(args)
                    if args[1]=='ps' and not any(c[1]=='rm' for c in commands):
                        return (commands[0][commands[0].index('--name')+1]+'\n').encode()
                    return b''
                return command(args,data)
            with patch.dict(os.environ,env),patch('run.get',get),patch('run.Hosted',factory), \
                 patch('run.command',mock_command),patch('postgres.command',mock_command),patch('run.local_docker',lambda:None),redirect_stdout(output),redirect_stderr(output):
                self.assertEqual(main(),0,output.getvalue())
                commands.clear()
                policy['free_capacity_verified']=False
                os.environ['BACKUP_POLICY_JSON']=json.dumps(policy)
                self.assertEqual(main(),1)
                self.assertEqual(commands,[])
            self.assertEqual(fixture_ref[0].signals,[True])
            self.assertNotIn('PRIVATE-TEST-PASSWORD',output.getvalue())
            self.assertNotIn('synthetic-client-id',output.getvalue())
            self.assertNotIn('synthetic-client-secret',output.getvalue())
            self.assertNotIn(ITEM['key'],output.getvalue())
    def test_workflow_boundaries(self):
        template=Path(__file__).with_name('backup.yml.template')
        text=(template if template.exists() else Path(__file__).resolve().parents[2]/'.github/workflows/backup.yml').read_text()
        for guard in ("vars.BACKUP_ENABLED == 'true'",'toJSON(github.event.repository.private)',
                      'runs-on: ubuntu-24.04','persist-credentials: false','timeout-minutes: 20',
                      'cancel-in-progress: false'):
            self.assertIn(guard,text)
        self.assertIn(f"github.repository == '{target.REPOSITORY}'",text)
        self.assertIn(f"github.repository_id == '{target.REPOSITORY_ID}'",text)
        self.assertIn('BACKUP_POLICY_SHA256',text)
        for key in ('BACKUP_DRIVE_CLIENT_ID','BACKUP_DRIVE_CLIENT_SECRET'):
            self.assertIn(key+': ${{ secrets.'+key+' }}',text)
        for forbidden in ('pull_request:', 'pull_request_target:', 'upload-artifact', 'cache@', 'npm ci', 'issues: read'):
            self.assertNotIn(forbidden,text)
    def test_rendered_workflow_bindings_match_target(self):
        template=Path(__file__).with_name('backup.yml.template')
        text=(template if template.exists() else Path(__file__).resolve().parents[2]/'.github/workflows/backup.yml').read_text()
        rendered=text.replace(target.REPOSITORY,REPOSITORY).replace(target.REPOSITORY_ID,REPOSITORY_ID)
        with patch.object(target,'REPOSITORY',REPOSITORY),patch.object(target,'REPOSITORY_ID',REPOSITORY_ID), \
             patch.object(Path,'read_text',return_value=rendered):
            self.test_workflow_boundaries()
        for wrong in (rendered.replace(REPOSITORY_ID,'999229'),rendered.replace(REPOSITORY,'Finn84FIN/wrong-repository')):
            with patch.object(target,'REPOSITORY',REPOSITORY),patch.object(target,'REPOSITORY_ID',REPOSITORY_ID), \
                 patch.object(Path,'read_text',return_value=wrong),self.assertRaises(AssertionError):
                self.test_workflow_boundaries()
    def test_sealed_policy_and_inert_template(self):
        policy=self.policy()
        raw=json.dumps(policy)
        checksum=digest(json.dumps(policy,sort_keys=True,separators=(',',':')).encode())
        self.assertEqual(approved_policy(raw,checksum),policy)
        for expected in (None,'','REPLACE_WITH_APPROVED_POLICY_SHA256','0'*64):
            with self.subTest(expected=expected),self.assertRaisesRegex(Failure,'setup_review'):
                approved_policy(raw,expected)
        changed=self.policy();changed['drive_folder']='another-folder'
        with self.assertRaisesRegex(Failure,'setup_review'): approved_policy(json.dumps(changed),checksum)
        with patch('backup.REPOSITORY','Finn84FIN/movie-night-backups'):
            with self.assertRaisesRegex(Failure,'unconfigured'):policy_guard(self.policy(),self.context(),self.recipient)
        with patch('backup.REPOSITORY','Finn84FIN/movie-night'):
            with self.assertRaisesRegex(Failure,'unconfigured'):policy_guard(self.policy(),self.context(),self.recipient)
    def test_entry_rejects_wrong_public_identity_before_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            event=Path(tmp)/'event.json'
            event.write_text(json.dumps({'repository':{'private':False,'id':int(REPOSITORY_ID)}}))
            env=dict(GITHUB_EVENT_PATH=str(event),GITHUB_REPOSITORY=REPOSITORY,
                     GITHUB_REPOSITORY_ID=REPOSITORY_ID)
            good={'private':False,'full_name':REPOSITORY,'id':int(REPOSITORY_ID),'default_branch':'main'}
            for key,value in [('private',True),('private',None),('full_name','Finn84FIN/movie-night'),
                              ('id',1),('default_branch','other')]:
                with self.subTest(key=key),patch.dict(os.environ,env), \
                     patch('run.github_read',return_value=dict(good,**{key:value})), \
                     patch('run.command') as tool,patch('run.Hosted') as hosted, \
                     patch('run.signal_healthcheck'),redirect_stderr(io.StringIO()):
                    self.assertEqual(main(),1)
                    tool.assert_not_called();hosted.assert_not_called()
            with patch.dict(os.environ,env),patch('run.REPOSITORY','Finn84FIN/movie-night-backups'), \
                 patch('run.github_read') as api,patch('run.signal_healthcheck'),redirect_stderr(io.StringIO()):
                self.assertEqual(main(),1);api.assert_not_called()
    def test_storage_info_fingerprint_and_version(self):
        adapter=Hosted.__new__(Hosted);adapter.root='https://example.test/storage/v1';adapter.headers={}
        info=dict(id=ITEM['id'],name=ITEM['key'],bucket_id=ITEM['bucket'],size=ITEM['size'],
                  version=ITEM['version'],etag='"'+ETAG+'"')
        def response(url,*args):
            return json.dumps(info).encode() if '/info/authenticated/' in url else DATA
        with patch('run.get',response):
            self.assertEqual(adapter.object_bytes(ITEM),(DATA,ETAG,ETAG))
            info['version']='changed'
            with self.assertRaisesRegex(Failure,'object_identity'): adapter.object_bytes(ITEM)
    def test_missing_drive_client_stops_before_provider_or_capture(self):
        for key in ('BACKUP_DRIVE_CLIENT_ID','BACKUP_DRIVE_CLIENT_SECRET'):
            for value in (None,'',' \t\n'):
                with self.subTest(key=key,value=value),patch.dict(os.environ), \
                     patch('run.get') as provider,patch('run.github_read') as github, \
                     patch('run.command') as tool,patch('run.Hosted') as capture, \
                     patch('run.signal_healthcheck'),redirect_stderr(io.StringIO()) as output:
                    if value is None:os.environ.pop(key,None)
                    else:os.environ[key]=value
                    os.environ.update(GITHUB_REPOSITORY=REPOSITORY,GITHUB_REPOSITORY_ID=REPOSITORY_ID)
                    self.assertEqual(main(),1)
                    self.assertEqual(output.getvalue(),'backup: drive_client\n')
                    provider.assert_not_called();github.assert_not_called()
                    tool.assert_not_called();capture.assert_not_called()
                    # Direct construction must also fail before config/provider I/O.
                    with self.assertRaisesRegex(Failure,'^drive_client$'):
                        Hosted(None,self.policy(),'unused-directory',self.recipient)
                    provider.assert_not_called()
    def test_drive_client_isolated_environment_and_sanitized_failure(self):
        with tempfile.TemporaryDirectory() as work:
            policy=self.policy()
            env=dict(BACKUP_STORAGE_KEY='private-storage-sentinel',
                     BACKUP_DRIVE_TOKEN='{"refresh_token":"private-token-sentinel"}',
                     BACKUP_DRIVE_CLIENT_ID='private-client-sentinel.apps.googleusercontent.com',
                     BACKUP_DRIVE_CLIENT_SECRET='private-secret-sentinel',
                     RCLONE_CONFIG='inherited.conf',RCLONE_CONFIG_MN_CLIENT_ID='wrong-client',
                     RCLONE_CONFIG_MN_CLIENT_SECRET='wrong-secret',RCLONE_DRIVE_SCOPE='drive',
                     RCLONE_CONFIG_MN_TOKEN_URL='https://wrong.example.test',
                     BACKUP_DB_PASSWORD='private-database-sentinel')
            folder=dict(id=policy['drive_folder'],name='Movie Night production backups',
                        mimeType='application/vnd.google-apps.folder')
            def tool(args,data=None,env=None):
                self.assertEqual(args[:2],['rclone','--config'])
                self.assertEqual(Path(args[2]).read_text(),'')
                self.assertIsNone(data)
                self.assertEqual(env['RCLONE_CONFIG_MN_CLIENT_ID'],os.environ['BACKUP_DRIVE_CLIENT_ID'])
                # OAuth OverrideCredentials in rclone 1.75.2 uses plain text.
                self.assertEqual(env['RCLONE_CONFIG_MN_CLIENT_SECRET'],os.environ['BACKUP_DRIVE_CLIENT_SECRET'])
                self.assertEqual(env['RCLONE_CONFIG_MN_SCOPE'],'drive.file')
                self.assertEqual(env['RCLONE_CONFIG_MN_ROOT_FOLDER_ID'],policy['drive_folder'])
                self.assertEqual({k for k in env if k.startswith('RCLONE_')},
                    {'RCLONE_CONFIG_MN_'+k for k in ('TYPE','SCOPE','CLIENT_ID','CLIENT_SECRET','ROOT_FOLDER_ID','TOKEN')})
                self.assertFalse(any(k.startswith('BACKUP_') for k in env))
                for value in ('private-client-sentinel','private-secret-sentinel','private-token-sentinel'):
                    self.assertNotIn(value,' '.join(args))
                if 'query' in args:return json.dumps([folder]).encode()
                return json.dumps({'free':policy['max_bundle_bytes']+1}).encode()
            with patch.dict(os.environ,env),patch('run.get',return_value=b'{"id":"profile-avatars","public":false}'), \
                 patch('run.command',side_effect=tool) as process:
                adapter=Hosted(None,policy,work,self.recipient)
                self.assertEqual(process.call_count,2)
                self.assertEqual(list(Path(work).iterdir()),[adapter.config])
                self.assertEqual(adapter.config.read_text(),'')
                # The real subprocess wrapper suppresses raw stderr even if a
                # provider/tool echoes credentials in its error response.
                import subprocess
                with patch('postgres.subprocess.run',side_effect=subprocess.CalledProcessError(
                        1,['rclone'],stderr=b'private-client-sentinel private-secret-sentinel')):
                    with self.assertRaisesRegex(Failure,'^tool_failed$'):
                        command(['rclone'],env=adapter.remote_env)
    def test_live_adapter_rejects_wrong_folder_or_capacity_before_capture(self):
        with tempfile.TemporaryDirectory() as work:
            policy=self.policy()
            env={'BACKUP_STORAGE_KEY':'synthetic','BACKUP_DRIVE_TOKEN':'{"refresh_token":"synthetic"}'}
            def metadata(url,*args): return b'{"id":"profile-avatars","public":false}'
            def rclone(adapter,args):
                return json.dumps([{'id':'wrong','name':'Movie Night production backups','mimeType':'application/vnd.google-apps.folder'}]
                                  if args[:2]==['backend','query'] else {'free':0}).encode()
            with patch.dict(os.environ,env),patch('run.get',metadata),patch.object(Hosted,'rclone',rclone):
                with self.assertRaisesRegex(Failure,'drive_folder'): Hosted(None,policy,work,self.recipient)
            def no_space(adapter,args):
                return json.dumps([{'id':policy['drive_folder'],'name':'Movie Night production backups','mimeType':'application/vnd.google-apps.folder'}]
                                  if args[:2]==['backend','query'] else {'free':0}).encode()
            with patch.dict(os.environ,env),patch('run.get',metadata),patch.object(Hosted,'rclone',no_space):
                with self.assertRaisesRegex(Failure,'drive_capacity'): Hosted(None,policy,work,self.recipient)
    def test_live_adapter_reads_real_drive_folder_metadata(self):
        with tempfile.TemporaryDirectory() as work:
            policy=self.policy()
            env={'BACKUP_STORAGE_KEY':'synthetic','BACKUP_DRIVE_TOKEN':'{"refresh_token":"synthetic"}'}
            expected={'id':policy['drive_folder'],'name':'Movie Night production backups',
                      'mimeType':'application/vnd.google-apps.folder'}
            calls=[]
            def reply(adapter,args):
                calls.append(args)
                # StatJSON's synthetic root has no ID. It must not be used.
                if args[0]=='lsjson':return b'{"Path":"","Name":"","IsDir":true}'
                if args[:3]==['backend','query','mn:']:
                    self.assertIn("name = 'Movie Night production backups'",args[3])
                    self.assertIn("mimeType = 'application/vnd.google-apps.folder'",args[3])
                    self.assertIn('trashed = false',args[3])
                    return json.dumps([dict(expected,id='same-name-other-folder'),expected]).encode()
                self.assertEqual(args,['about','mn:','--json'])
                return json.dumps({'free':policy['max_bundle_bytes']+1}).encode()
            with patch.dict(os.environ,env),patch('run.get',return_value=b'{"id":"profile-avatars","public":false}'), \
                 patch.object(Hosted,'rclone',reply):
                adapter=Hosted(None,policy,work,self.recipient)
                self.assertEqual(adapter.remote_env['RCLONE_CONFIG_MN_ROOT_FOLDER_ID'],policy['drive_folder'])
                self.assertEqual(adapter.remote_env['RCLONE_CONFIG_MN_SCOPE'],'drive.file')
                self.assertTrue(all(c[0]!='lsjson' for c in calls))
                for response in (None,[],[dict(expected,id='wrong')],[dict(expected,mimeType='text/plain')],
                                 [dict(expected,name='renamed')],[dict(expected,trashed=True)],
                                 [expected,expected],{'ID':policy['drive_folder'],'IsDir':True}):
                    with self.subTest(response=response),patch.object(Hosted,'rclone',return_value=json.dumps(response).encode()), \
                         self.assertRaisesRegex(Failure,'drive_folder'):
                        Hosted(None,policy,work,self.recipient)


if __name__=='__main__': unittest.main()
