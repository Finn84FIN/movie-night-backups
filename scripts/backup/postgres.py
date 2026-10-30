"""Isolated PostgreSQL capture/restore. Docker image and schema set are fixed."""
import json
import os
import re
import subprocess
import time
import uuid
import base64
import csv
from pathlib import Path
from backup import Failure, IMAGE, digest, require

SCHEMAS = ("public", "auth", "storage", "extensions", "supabase_migrations")
STORAGE_IMAGE = "public.ecr.aws/supabase/storage-api@sha256:528ec49c3c32561908b07ee91bced7f8456f3b688164e341eaa422441767a0bd"
ROLE_SQL = """select coalesce(json_agg(json_build_object('name',rolname,
 'super',rolsuper,'inherit',rolinherit,'create_role',rolcreaterole,
 'create_db',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,
 'bypass',rolbypassrls,'connections',rolconnlimit,'config',coalesce(rolconfig,array[]::text[])) order by rolname),'[]') from pg_roles where rolname !~ '^pg_';"""
MEMBERS_SQL = """select coalesce(json_agg(json_build_object('role',r.rolname,
 'member',m.rolname,'admin',a.admin_option,'inherit',a.inherit_option,
 'set',a.set_option,'grantor',g.rolname) order by r.rolname,m.rolname,g.rolname),'[]')
 from pg_auth_members a join pg_roles r on r.oid=a.roleid join pg_roles m on m.oid=a.member
 join pg_roles g on g.oid=a.grantor;"""
EXT_SQL = """select coalesce(json_agg(json_build_object('name',e.extname,'version',e.extversion,
 'schema',n.nspname,'owner',pg_get_userbyid(e.extowner)) order by e.extname),'[]') from pg_extension e
 join pg_namespace n on n.oid=e.extnamespace where n.nspname in ('public','auth','storage','extensions')
 and e.extname not in ('pg_cron','pg_net','supabase_vault','pgsodium');"""
INVENTORY_SQL = """select coalesce(json_agg(json_build_object('id',id,'bucket',bucket_id,'key',name,'version',version,
 'size',(metadata->>'size')::bigint,'etag',trim(both '"' from metadata->>'eTag')) order by id),'[]') from storage.objects;"""
REFERENCES_SQL = """select coalesce(json_agg(object_key),'[]') from public.profile_avatar_assets where id in
 (select custom_id from public.profile_avatars union select discord_id from public.profile_avatars);"""


def ident(value):
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def setting_value(key,value):
    # List GUCs must be separate SQL values. Quoting the entire comma-separated
    # string makes it a single schema/library name and changes its meaning.
    if key in ('search_path','session_preload_libraries') and value:
        values=next(csv.reader([value],skipinitialspace=True,strict=True))
        return ', '.join(ident(part) for part in values)
    return literal(value)


def base_env():
    return {key:os.environ[key] for key in ('PATH','HOME','USERPROFILE','SYSTEMROOT','HOMEDRIVE','HOMEPATH',
            'TMP','TEMP','TMPDIR','LANG','LC_ALL','DOCKER_CONFIG') if key in os.environ}


def command(args, data=None, env=None):
    try:
        return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=base_env() if env is None else env, check=True, timeout=300).stdout
    except (OSError, subprocess.SubprocessError):
        raise Failure("tool_failed") from None


def normalized_schema(data):
    # Normalize ONLY the pinned client's outer wrapper. Comment-looking lines
    # and CR/LF inside dollar-quoted function strings are meaningful schema.
    lines=data.split(b'\n')
    start=next((i for i,line in enumerate(lines) if line.startswith(b'SET ')),None)
    require(start is not None and start < 30, 'schema_dump_header')
    keys=[line[len(b'\\restrict '):] for line in lines[:start] if line.startswith(b'\\restrict ')]
    require(len(keys)==1 and re.fullmatch(rb'[A-Za-z0-9]+',keys[0]), 'schema_dump_header')
    end=len(lines)-1
    while end>=0 and lines[end]==b'': end-=1
    require(lines[end]==b'\\unrestrict '+keys[0], 'schema_dump_footer')
    header=[line for line in lines[:start] if not line.startswith(
        (b'\\restrict ',b'-- Dumped from database version '))]
    return b'\n'.join(header+lines[start:end])


def local_docker():
    require(not any(os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')), 'docker_override')
    contexts=json.loads(command(['docker','context','inspect']))
    require(len(contexts)==1 and contexts[0]['Endpoints']['docker']['Host'] in
            ('unix:///var/run/docker.sock','npipe:////./pipe/dockerDesktopLinuxEngine'), 'docker_remote')


def remove_container(name):
    require(re.fullmatch(r'mn-backup-(restore|storage|client|probe)-[0-9a-f]{24,32}',name), 'container_identity')
    query=['docker','ps','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']
    present=command(query).decode().strip()
    if not present:
        return
    require(present==name,'container_identity')
    command(['docker','rm','--force',name])
    require(not command(query).strip(),'container_cleanup')


class Database:
    def __init__(self, container, user="supabase_admin", source_env=None):
        self.container, self.user, self.source_env = container, user, source_env

    def run(self, tool, args=(), data=None):
        options = []
        if self.source_env:
            for key in ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT"):
                options += ["-e", key]
        else:
            args = ["-U", self.user, "-d", "postgres", *args]
        return command(["docker", "exec", "-i", *options, self.container, tool, *args], data,
                       self.source_env)

    def sql(self, text):
        return self.run("psql", ["-XqAt", "-v", "ON_ERROR_STOP=1"], text.encode()).decode().strip()

    def json(self, sql):
        try:
            return json.loads(self.sql(sql))
        except (ValueError, TypeError):
            raise Failure("database_metadata") from None

    def schema(self):
        return normalized_schema(self.run("pg_dump", ["--schema-only", *schema_args()]))


def schema_args():
    return ["--schema=" + schema for schema in SCHEMAS]


def start_sandbox():
    local_docker()
    name = "mn-backup-restore-" + uuid.uuid4().hex
    try:
        env=base_env();env['POSTGRES_PASSWORD']=uuid.uuid4().hex
        command(["docker", "run", "--detach", "--name", name, "--network", "none",
                 "--tmpfs", "/var/lib/postgresql/data", "--env", "POSTGRES_PASSWORD",
                 IMAGE, "postgres", "-D", "/var/lib/postgresql/data"],env=env)
        db = Database(name)
        for _ in range(60):
            try:
                db.sql("select 1;")
                return db
            except Failure:
                time.sleep(1)
        raise Failure("restore_bootstrap")
    except Exception:
        remove_container(name)
        raise


def stop_sandbox(db):
    if db:
        remove_container(db.container)


def prerequisites(db):
    roles = db.json(ROLE_SQL)
    allowed = {'statement_timeout','lock_timeout','search_path','log_statement',
               'idle_in_transaction_session_timeout','session_preload_libraries','default_transaction_read_only'}
    for role in roles:
        require(all(c.split('=',1)[0] in allowed for c in role['config']), 'role_configuration')
    return dict(roles=roles, memberships=db.json(MEMBERS_SQL),
                namespace_layout=db.json("select json_agg(json_build_object('name',nspname,'owner',pg_get_userbyid(nspowner)) order by nspname) from pg_namespace where nspname !~ '^pg_(toast_)?temp';"),
                extensions=db.json(EXT_SQL), schema_sha256=digest(db.schema()),
                schemas=db.json("select json_agg(json_build_object('name',nspname,'owner',pg_get_userbyid(nspowner)) order by nspname) from pg_namespace where nspname in ('public','auth','storage','extensions','supabase_migrations');"),
                server_version=db.sql("show server_version_num;"), image=IMAGE, storage_image=STORAGE_IMAGE)


def restore(archive, pre):
    require(pre.get("image") == IMAGE and pre.get("server_version", "").startswith("17"), "database_version")
    require(pre.get('storage_image') == STORAGE_IMAGE, 'storage_version')
    db = start_sandbox()
    try:
        db.sql("DROP SCHEMA public,auth,storage,extensions CASCADE;")
        existing = set(db.json("select json_agg(rolname) from pg_roles;"))
        for role in pre["roles"]:
            name = ident(role["name"])
            if role["name"] not in existing:
                db.sql("CREATE ROLE " + name + ";")
            flags = [("super", "SUPERUSER"), ("inherit", "INHERIT"), ("create_role", "CREATEROLE"),
                     ("create_db", "CREATEDB"), ("login", "LOGIN"), ("replication", "REPLICATION"), ("bypass", "BYPASSRLS")]
            db.sql("ALTER ROLE " + name + " WITH " + " ".join(
                ("" if role[k] else "NO") + flag for k, flag in flags) + ";")
            db.sql('ALTER ROLE ' + name + ' CONNECTION LIMIT ' + str(int(role['connections'])) + ';')
            db.sql("ALTER ROLE " + name + " RESET ALL;")
            for config in role['config']:
                key, value = config.split('=',1)
                db.sql("ALTER ROLE " + name + " SET " + ident(key) + " TO " + setting_value(key,value) + ";")
        for m in db.json(MEMBERS_SQL):
            db.sql("REVOKE " + ident(m['role']) + " FROM " + ident(m['member'])
                   + " GRANTED BY " + ident(m['grantor']) + " CASCADE;")
        for m in pre["memberships"]:
            db.sql("GRANT " + ident(m["role"]) + " TO " + ident(m["member"]) + " WITH ADMIN "
                   + str(m["admin"]).upper() + ", INHERIT " + str(m["inherit"]).upper()
                   + ", SET " + str(m["set"]).upper() + " GRANTED BY " + ident(m['grantor']) + ";")
        # Schema-filtered pg_dump excludes extension installation statements.
        # Recreate their exact versions before restoring dependent defaults.
        for ext in pre["extensions"]:
            require(ext["schema"] in SCHEMAS, "extension")
            owner=next((r for r in pre['roles'] if r['name']==ext['owner']),None)
            require(owner is not None,'extension_owner')
            # Bootstrap only: install untrusted extensions under their captured
            # owner, then restore that owner's exact privilege flags atomically.
            elevate='' if owner['super'] else 'ALTER ROLE '+ident(ext['owner'])+' SUPERUSER; '
            reset='' if owner['super'] else 'ALTER ROLE '+ident(ext['owner'])+' NOSUPERUSER; '
            db.sql("BEGIN; " + elevate + "CREATE SCHEMA IF NOT EXISTS " + ident(ext["schema"]) + "; GRANT USAGE, CREATE ON SCHEMA "
                   + ident(ext["schema"]) + " TO " + ident(ext["owner"]) + "; SET ROLE " + ident(ext["owner"]) + "; CREATE EXTENSION "
                   + ident(ext["name"]) + " WITH SCHEMA " + ident(ext["schema"])
                   + " VERSION " + literal(ext["version"]) + "; RESET ROLE; " + reset + 'COMMIT;')
        command(["docker", "exec", "-i", db.container, "sh", "-c", "cat > /tmp/capture.dump"], archive)
        toc = db.run("pg_restore", ["--list", "/tmp/capture.dump"])
        existing_schemas = set(db.json("select json_agg(nspname) from pg_namespace;"))
        lines = []
        for line in toc.decode().splitlines():
            # Extension schemas already exist; keep all ACLs/owners/functions.
            match = re.search(r" SCHEMA - (\S+) ", line)
            if not match or match[1] not in existing_schemas:
                lines.append(line)
        command(["docker", "exec", "-i", db.container, "sh", "-c", "cat > /tmp/toc"], "\n".join(lines).encode())
        db.run("pg_restore", ["--exit-on-error", "--use-list=/tmp/toc", "/tmp/capture.dump"])
        for schema in pre["schemas"]:
            db.sql("ALTER SCHEMA " + ident(schema["name"]) + " OWNER TO " + ident(schema["owner"]) + ";")
        require(digest(db.schema()) == pre["schema_sha256"], "restored_schema")
        invalid = db.sql("""select count(*) from pg_constraint c join pg_namespace n on n.oid=c.connamespace
          where n.nspname in ('public','auth','storage') and not c.convalidated;""")
        require(invalid == "0", "constraints")
        require(db.sql("select count(*) from storage.buckets where public;") == "0", "public_bucket")
        return db
    except Exception:
        stop_sandbox(db)
        raise


class PostgresCapture:
    """The source only receives SQL reads/pg_dump, never restore statements."""
    def __init__(self, source, policy):
        self.source, self.policy, self.restored = source, policy, None

    def dump(self):
        pre = prerequisites(self.source)
        require(pre["schema_sha256"] == self.policy["schema_sha256"], "schema_drift")
        require(pre["server_version"] == self.policy["source_version"], "version_drift")
        require(digest(json.dumps(pre,sort_keys=True,separators=(',',':')).encode()) == self.policy['prerequisites_sha256'], 'prerequisites_drift')
        size = int(self.source.sql("select pg_database_size(current_database());"))
        require(size < self.policy["max_database_bytes"] <= 500 * 1024 * 1024, "capacity")
        archive = self.source.run("pg_dump", ["--format=custom", *schema_args()])
        require(pre == prerequisites(self.source), "schema_drift")
        return archive, pre

    def restore_and_inspect(self, archive, pre):
        self.restored = restore(archive, pre)
        inventory = self.restored.json(INVENTORY_SQL)
        references = self.restored.json(REFERENCES_SQL)
        counts = {}
        for table in ("auth.users", "auth.identities", "public.profiles", "public.movie_spaces",
                      "public.movie_space_memberships", "public.movie_space_watchlist", "public.movie_nights",
                      "public.movie_space_watch_records", "public.movie_space_movie_ratings"):
            counts[table] = int(self.restored.sql("select count(*) from " + table + ";"))
        return inventory, references, counts

    def verify_restored_objects(self, objects, root):
        local_docker()
        # Real Supabase file backend, with no network listener or credentials.
        # RLS/private bucket metadata are checked in the independent restored DB;
        # this stage proves that the captured key/version/bytes are readable.
        name='mn-backup-storage-'+uuid.uuid4().hex
        script="""
        const fs=require('node:fs'),{Readable}=require('node:stream'),crypto=require('node:crypto');
        const {FileBackend}=require('/app/dist/storage/backend/file.js');
        (async()=>{
          const x=JSON.parse(fs.readFileSync(0,'utf8'));
          const b=Object.create(FileBackend.prototype); b.filePath='/recovered';b.etagAlgorithm='md5';
          const key='stub/'+x.bucket+'/'+x.key;
          await b.uploadObject('stub',key,x.version,Readable.from(Buffer.from(x.data,'base64')),'image/webp','no-cache');
          const result=await b.getObject('stub',key,x.version);
          const hash=crypto.createHash('sha256');for await(const part of result.body)hash.update(part);
          process.stdout.write(hash.digest('hex'));
        })().catch(()=>process.exit(1));
        """
        try:
            command(['docker','run','--detach','--name',name,'--network','none','--user','0',
                     '--tmpfs','/recovered','--env','AUTH_JWT_SECRET=synthetic-offline-recovery-only-228',
                     '--env','DATABASE_URL=postgresql://synthetic:synthetic@127.0.0.1:1/offline',
                     '--env','STORAGE_BACKEND=file','--env','STORAGE_FILE_BACKEND_PATH=/recovered',
                     '--entrypoint','sleep',STORAGE_IMAGE,'infinity'])
            for obj in objects:
                payload=dict(bucket=obj['bucket'],key=obj['key'],version=obj['version'],
                             data=base64.b64encode((Path(root)/obj['file']).read_bytes()).decode())
                actual=command(['docker','exec','-i',name,'node','-e',script],json.dumps(payload).encode())
                require(actual.decode()==obj['sha256'], 'restored_object')
        finally:
            remove_container(name)

    def close_restore(self):
        db, self.restored = self.restored, None
        stop_sandbox(db)
