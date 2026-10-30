# Private encrypted backups

This standalone package prepares a daily hosted backup without depending on an
owner's PC. It is an **inert template**, not an activated production service.
`target.py` and both workflows deliberately contain unconfigured placeholders.
They fail closed. The application repository stays private; this package needs
no application checkout, migrations, private issues or private-repository token.
Authoritative decisions remain in the private project's existing Tasks.

## Publication and trust boundary

Only the reviewed allowlisted files belong in a fresh public operations repository.
Do not fork/mirror the app, copy its history, environment files, data, screenshots,
authority issues or production schema dumps. The included SQL is a purpose-written
synthetic fixture, not the application's migrations or a production schema export.
The package manifest records the SHA256 of each exact publication file. Review the
bytes and licensing before publication; no redistribution license has been selected
by this preparation. No upstream library code or binary is bundled. Tools/images
are obtained from their pinned upstream releases and retain upstream terms.

Repository creation/publication, configuration, provider access, trial exports and
activation each stay within the later explicitly approved setup package. Do not
use a template placeholder as an actual repository, hash, project or account.
No workflow is installed in the private app repository by this preparation.

## What a daily success proves

At 03:37 UTC, an enabled job captures one consistent PostgreSQL logical dump,
restores it into new isolated database services, derives the complete private
picture inventory from that snapshot and captures its bytes. Snapshot ETags,
object IDs/versions/sizes and byte checksums must agree. Missing or changing objects
invalidate the attempt. One fresh whole-capture retry is allowed; never omit data
to make it pass. Restore checks preserve schema, roles/settings/memberships, Auth
relationships, constraints, grants/RLS and private bucket state. Object bytes are
written/read through the pinned Supabase file backend, without serving HTTP.

The verified dump, object bytes and private manifest are encrypted with age before
upload to the fixed private Drive folder. Immutable unique generations preserve
earlier good backups. The entire ciphertext is downloaded and hashed again.
Normal workspace/container cleanup completes before success is signaled to the
independent monitor. No automatic retention deletion exists.

Public output contains only a generation identifier, aggregate counts, ciphertext
checksum and evidence labels. No SQL, object paths, usernames, hashes of account
passwords, folder/account identifiers, policy body, provider errors, keys or tokens
belong in logs, caches, artifacts or commits. A receipt might be:

```json
{"generation":"mn-TIMESTAMP-UUID","validation":"snapshot-restored","encrypted_readback":"passed","recovery_drill":"not-performed","object_count":1,"ciphertext_sha256":"OPAQUE_HASH"}
```

The daily runner has only the public age recipient, so it cannot prove decryption.
Only an owner-held-key download/decrypt/restore drill gives that particular
generation off-site recovery evidence. Perform one before launch, monthly and after
capture/encryption/restore changes. Daily success is not that drill's result.

## Zero additional cost

Use only standard `ubuntu-24.04` GitHub-hosted runners in the exact separately
verified **public** operations repository. Private, larger, paid and self-hosted
fallbacks are prohibited. Both workflows gate on exact name, immutable ID and
explicit public metadata. The runner independently verifies public API metadata,
default main branch and repository identity. A missing payload is not proof of
public visibility. Keep backup-specific hosted tests out of the private app repo.

Before any trial, independently verify free provider plans and enforceable blocks
that prevent paid overages, plus free database/egress/Drive/monitoring capacity.
Include reads, encrypted readback, retries and recovery drills. No budget estimate,
timeout or receipt boolean replaces provider-enforced safeguards. If those cannot
be established, stop for a free alternative. Never activate paid upgrades, add-ons,
automatic purchases, smaller incomplete captures or deletion of good generations.

Caps are 500 MiB database, 256 KiB per normalized picture, 256 MiB total picture
bytes, 512 MiB encrypted bundle and a 20-minute job. Policy may impose smaller
limits. Drive capacity is checked before capture/upload. Caps are not assurances
of available quota. Intended retention is 7 daily plus 4 weekly; a later approved
pruning rule is needed. Until then preserve every generation and stop on capacity.

## Separately approved setup

1. Fix the exact public repository name/ID/default branch and reviewed published
   commit. Bind the same identity in `target.py` and both workflow guards. Set
   `PROJECT_SHA256` and `DRIVE_ACCOUNT_SHA256` to the approved project/account
   hashes, not their plaintext values. Verify those hashes against the private
   approval. The backup cannot accept a different target merely through a variable.
   Keep providers/credentials unchanged during repository preparation.
2. Verify trusted workflow writers: any writer can potentially change privileged
   code. Adding one requires a trust decision. Later application commits cannot
   silently alter this repository's pinned backup code. Use read-only contents
   permission and no persisted checkout token. No private access token is needed.
3. Approve exact production identity, powerful credential access, free-capacity
   observations and a bounded real trial before preflight. Use only the project's
   IPv4 session pooler, port 5432, `postgres.PROJECT`, with certificate-verified
   TLS. No paid IPv4 add-on, relinking, password reset, schema repair or resume
   operation is implied. The approved metadata probe is:
   `python3 scripts/backup/probe.py HOST PROJECT`. It prompts for the password and
   returns only version/schema/prerequisite hashes and size. The project must match
   its reviewed hash. Do not run it against production during tooling preparation.
4. Generate an age key on an owner-controlled recovery device, store the identity
   in a password manager and separately protected recovery copy if desired. Test
   recovery. Only its public recipient and SHA256 enter the job. Losing the identity
   loses recovery of backups encrypted to it; the runner cannot recover that key.
5. Create an owner-controlled Google OAuth client for a desktop/CLI application
   in the approved Google account/project, without enabling billing. Use that
   same client ID and client secret when authorizing rclone with `drive.file`;
   a token issued to the shared or a different client must be reauthorized, not
   silently reused. The runtime requires both credentials and never falls back
   to rclone's retiring shared client. See [rclone client setup](https://rclone.org/drive/#making-your-own-client-id).
   Check consent publishing status, refresh-token expiry/revocation constraints
   and unattended refresh before activation; obtaining an initial access token
   is not proof of a durable grant. Do not broaden scopes or enable billing to
   bypass a setup problem. Credential/consent entry stays owner-controlled.
   Authorize rclone with `drive.file` in the approved account and have it create
   the approved private folder. Independently verify account, folder ID, no link/
   public sharing and actual OAuth grant. `drive.file` is app-scoped, not a strict
   folder permission boundary; the fixed root constrains commands, not token power.
   Do not reuse a broader token or broaden consent silently.
   Name the folder `Movie Night production backups`. Preflight reads real Drive
   folder metadata using the pinned rclone backend query, then matches the exact
   approved ID, name/type and non-trashed state; same-name folders are not fallback
   destinations. Root `lsjson --stat` has no folder ID and is not identity proof.
6. Create a Healthchecks Hobbyist check (24 hours plus 2 hours grace), fixed owner
   recipient and secret ping URL. Verify failure delivery and missed-run detection
   in the later approved trial. GitHub failure emails cannot detect a job that never
   starts, including schedules disabled after public-repository inactivity.
7. Enter these secrets directly in the public operations repository's GitHub secret
   interfaces, never in chat, inputs, command arguments/history or logs:

   | Secret | Actual power |
   | --- | --- |
   | `BACKUP_DB_PASSWORD` | Project postgres/admin; commands read, but the credential is powerful |
   | `BACKUP_STORAGE_KEY` | Project service-role, including elevated Auth/Storage access |
   | `BACKUP_DRIVE_TOKEN` | rclone token JSON with independently verified narrow OAuth grant |
   | `BACKUP_DRIVE_CLIENT_ID` | Owner-controlled Google OAuth client matching the token |
   | `BACKUP_DRIVE_CLIENT_SECRET` | That client's plain Google secret, securely entered with its ID |
   | `BACKUP_HEALTHCHECK_URL` | Can change the independent check's reported status |

   Supply the client secret as plain text, not `rclone obscure` output: pinned
   [rclone 1.75.2 OAuth overrides](https://github.com/rclone/rclone/blob/v1.75.2/lib/oauthutil/oauthutil.go#L412-L432)
   use the supplied string directly. The adapter passes ID/secret/token only in
   the isolated rclone child environment, with an empty temporary config; never
   put them in arguments, public variables, logs or committed configuration.
   Missing/blank ID or secret stops before data-provider access or capture.
   Client ownership does not make the refresh token or client secret public.

   A narrower database role requires proof of complete capture privileges and
   separate approval. No team-wide management or private repository token.
8. Prepare the final private operational policy, recipient and full reviewed public
   backup commit. Record approval in the existing private execution Task. Example
   below is intentionally unusable and includes no real target/account/Drive data:

```json
{
  "enabled": false,
  "repository": "Finn84FIN/APPROVED_PUBLIC_OPERATIONS_REPOSITORY",
  "repository_id": "APPROVED_IMMUTABLE_ID",
  "project": "APPROVED_PROJECT",
  "code_sha": "REVIEWED_PUBLIC_BACKUP_COMMIT",
  "expires": "2000-01-01T00:00:00Z",
  "recipient_sha256": "PUBLIC_RECIPIENT_SHA256",
  "drive_account": "OWNER_VERIFIED_ACCOUNT",
  "drive_folder": "OWNER_VERIFIED_PRIVATE_FOLDER",
  "setup_review_url": "PRIVATE_EXECUTION_TASK_URL",
  "provider_free_blocks_verified": false,
  "free_capacity_verified": false,
  "source_version": "FROM_APPROVED_PROBE",
  "schema_sha256": "FROM_APPROVED_PROBE",
  "prerequisites_sha256": "FROM_APPROVED_PROBE",
  "pooler_host": "APPROVED_SESSION_POOLER_HOST",
  "database_user": "postgres.APPROVED_PROJECT",
  "max_database_bytes": 500000000,
  "max_bundle_bytes": 536870912
}
```

   Expiry must be in the next 31 days. Optional `source_application` is restricted
   to commit/version/verification/evidence_url and is attributed setup evidence,
   not a live deployment observation. Operational config and private issue content
   stay out of public commits/logs. The runner never follows the private issue URL.
9. Canonicalize the final policy using UTF-8 Python
   `json.dumps(policy, sort_keys=True, separators=(',', ':'))` and SHA256. The exact
   hash, code identity and scope must be owner-approved in the private Task, then
   independently read back. Transfer those exact bytes to `BACKUP_POLICY_JSON` and
   the approved hash to `BACKUP_POLICY_SHA256` through owner-controlled repository
   variable interfaces; set `BACKUP_RECIPIENT` and `BACKUP_CODE_SHA` similarly.
   Independently verify saved values against the approval before trial/activation.
   A hash is a consistency check, not an approval system: someone able to change
   both variables or the workflow can bypass it. The trusted writer/config boundary
   is deliberate. The runner does no private issue lookup and stores no transcript.
   Renewal needs fresh approval and verified free capacity/recovery evidence; an
   unavailable or mismatched receipt stops execution.
10. Only an approved trial may set the policy enabled and `BACKUP_ENABLED=true`,
    dispatch once on main as the owner, and verify the real generation/drill,
    private Drive storage, cleanup and monitor. Recurring exports require explicit
    approval to leave those controls enabled. Publication alone enables nothing.

## Portable synthetic validation

Requires Python 3.12+, local Docker and the pinned tools; no app/Supabase stack or
provider credentials. Install `python3 scripts/backup/tools.py TOOL_DIRECTORY` and
put that directory on PATH, then run:

```sh
python3 scripts/backup/test_backup.py
python3 scripts/backup/test_postgres.py
```

The integration entry point first checks the local Linux Docker engine and pulls
both digest-pinned images explicitly before starting disconnected services.
Acquisition failures are distinguished from startup failures; a local pass with
cached layers is still not fresh hosted Linux evidence. Bootstrap failures report
only the stage, an allowlisted error category and exit status, never raw tool output. This
diagnostic path exists only in the fixture test; production error redaction and
the disconnected restore-service network remain unchanged. A failed hosted run
still requires investigation: the category is evidence, not an automatic retry,
permission change, image substitution or recovery pass.

The test-only bindings exist in memory; target files remain unconfigured. The
integration creates a small synthetic database from `fixture.sql`, verifies a
non-superuser capture, exact roles/settings/memberships and grants/RLS, bcrypt,
snapshot inventory, versioned Supabase file-backend bytes, real age encryption/
decryption and independent cold restore. It accesses only new randomly named
disposable containers. It does not validate the entire application's production
schema or live provider permissions. Those remain later preflight/trial gates.
Public CI has no credentials, artifacts or caches and must actually run to count
as Linux coverage; green app CI or skipped public checks are not backup validation.

## Owner recovery drill

Download a successful generation from private Drive, match the receipt filename/
ciphertext SHA256 and bring the identity directly from the password manager into
a private temporary recovery directory outside Git. Use reviewed code, pinned
tools and a local Docker engine; remote Docker contexts/overrides are rejected.

```sh
python3 scripts/backup/recover.py /private/generation.tar.age /private/age-identity --restore
```

Decryption, archive-path validation, hashes, isolated database restore, reference
checks and actual file-backend byte reads run before cleanup. Without `--restore`,
the result proves only decryption/checksums. The tool explicitly cannot prove the
off-site origin of its input; attribute the real download and observer in the
private execution Task. Remove the exported identity using secure-device practice.
Windows Python may lack OS trust roots; use the OS downloader and exact pinned
tool digests rather than weakening TLS.

This does not start GoTrue/app HTTP, restore valid live sessions or recreate a
hosted service. Recreate provider configuration/credentials and reauthenticate
separately before reopening. Vault/cron/net/platform keys, schedules and database
login passwords are excluded; app Auth hashes/identities and data are preserved.
Unknown versions/role settings stop recovery rather than weakening validation.

## Failure and missed-run response

The owner inspects the last sanitized receipt and independent monitor. Missing,
expired or mismatched policy requires reapproval, not toggling around checks.
Schema/prerequisite/version drift needs cumulative review. Missing/changed object
bytes invalidate a capture, including an object queued for deletion. Whole capture
retries at most once; upload/readback errors do not overwrite older generations.
A Drive file without a success receipt is not a successful generation.

Capacity errors require approved free-capacity recovery or reviewed limits within
free quotas; never auto-prune, pay, repair source queues, freeze writes, pause
schedulers or restore production. On unsafe target/credential behavior, disable
only this launcher and obtain scoped credential recovery approval. On suspected
key disclosure, separately approve rotation and test a new generation; keep keys
needed by older retained generations protected.

Public schedules can stop after inactivity; the independent monitor must alert.
The owner checks source/configuration, expiry and public/free status before
re-enabling. SIGTERM/SIGINT cleanup is best effort; hard VM termination can prevent
cleanup. VM disposal is not secure-erasure proof, and a delayed/missed run leaves
the recovery point at the last successful generation.
