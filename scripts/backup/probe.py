"""One-time read-only metadata probe; requires separate named-host approval.
Never run this against production during Task228 repository preparation.
"""
import getpass
import json
import os
import re
import sys
import uuid
from backup import IMAGE, PROJECT_SHA256, Failure, digest, require
from postgres import Database, command, prerequisites, local_docker, base_env, remove_container


def probe(host, password, project):
    require(re.fullmatch(r'[a-z]{20}', project) and digest(project.encode()) == PROJECT_SHA256, 'project')
    require(re.fullmatch(r'aws-\d+-[a-z0-9-]+\.pooler\.supabase\.com',host), 'database_host')
    local_docker()
    name='mn-backup-probe-'+uuid.uuid4().hex
    try:
        command(['docker','run','--detach','--name',name,'--network','bridge','--entrypoint','sleep',IMAGE,'infinity'])
        env=dict(base_env(),PGHOST=host,PGPORT='5432',PGDATABASE='postgres',PGUSER='postgres.'+project,
                 PGPASSWORD=password,PGSSLMODE='verify-full',PGSSLROOTCERT='system')
        db=Database(name,source_env=env)
        pre=prerequisites(db)
        return dict(source_version=pre['server_version'],schema_sha256=pre['schema_sha256'],
                    prerequisites_sha256=digest(json.dumps(pre,sort_keys=True,separators=(',',':')).encode()),
                    database_bytes=int(db.sql('select pg_database_size(current_database());')))
    finally:
        remove_container(name)


if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'arguments')
        print(json.dumps(probe(sys.argv[1],getpass.getpass('Project database password (not stored): '),sys.argv[2])))
    except Exception as error:
        print('probe: '+(str(error) if isinstance(error,Failure) else 'failed'),file=sys.stderr)
        sys.exit(1)
