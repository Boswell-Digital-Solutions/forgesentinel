            # Runtime Boundary

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The implemented MVP is a TypeScript modular monolith with a shadow-mode intelligence pipeline.

Nodes hold no authority credentials. The pipeline terminates at policy decisions and receipts unless an operator-approved capability is presented to an authority adapter.

## CSSA Watchdog Worker

`src/watchdog/` adds one supervised worker, `sentinel watch-cssa`. It polls all three of DataForge's `cloud-security` record families: decisions, authorizations, and outcomes. It runs four deterministic detectors: denial streak, quota-exceeded burst, approval-pending burst, and execution-failure burst. Outcomes carry no principal or tenant of their own. `AuthorizationIndex` resolves a subject by joining on `authorization_id`. The index is durable and pruned. An outcome with no matching authorization stays unattributed; the worker never guesses a subject. The worker converts each finding through the Forge-Agents §4 `CloudSecurityFinding` contract and feeds it to `SentinelRuntime.ingestSourceFindings`. The worker has no inbound surface. It makes outbound calls only. It requires a live `DATAFORGE_BASE_URL` and `DATAFORGE_CSSA_TOKEN`; no credential is built in. Prime's `promoteSingles()` now promotes all four finding types to a lone-signal incident.

## Producer Authentication

The Event Gateway (`src/spine/gateway.ts`) is an in-process class. It has no network ingress. Events reach it through `sentinel replay <file>` or through a library caller. The gateway authenticates each producer with HMAC-SHA256 over the payload hash. A signature-required producer or event family also needs a signature made with the same producer secret.

Producer secrets come from protected configuration (KI-SENTINEL-20261030-002). The source holds only the non-secret producer profiles (`STANDARD_PRODUCER_PROFILES` in `src/spine/producer_secrets.ts`).

- `SentinelRuntime` takes its producer registrations from the caller. It has no built-in default.
- `ProducerRegistry` is bound to one environment. It checks each registration when it is added, including a registration added after the runtime is built. It refuses to replace a key that is already registered.
- An empty list is valid. The gateway then refuses every event. `sentinel watch-cssa` uses an empty list, because it does not use the gateway.
- `loadProducerRegistrations(environment)` reads the file named by `SENTINEL_PRODUCER_SECRETS_FILE`. The file has the schema `forgesentinel.producer_secrets.v1`, an `environment`, and one `key_id` and `secret` for each standard producer.
- The loader opens the file once and checks the open file. It refuses these and throws `ProducerSecretsError`:
  - a missing variable;
  - a symlink, a path that is not a regular file, or a file that cannot be read;
  - on POSIX, a file that group or others can read or write, or a file owned by another user (Windows has no permission check);
  - a file for another environment, or an unknown field at the top level or in a producer entry;
  - a missing producer, an unknown producer, or one `key_id` used by two producers.
- Every environment refuses a secret that contains a control character. HMAC pads a short key with NUL bytes, so a secret of NUL bytes is the empty key.
- In `production` and `staging`, the runtime, the registry and the loader also refuse:
  - a secret with the published `test-secret-` prefix;
  - a secret with a character outside printable ASCII, or with a space;
  - a secret shorter than 32 characters, or with fewer than 10 distinct characters;
  - one secret shared by two producers.
- Generate a secret with, for example, `openssl rand -hex 32`.
- An error message never contains a secret value.
- `sentinel replay` reads `SENTINEL_ENVIRONMENT` (default `production`) and loads the secrets file. It exits with code 2 when the configuration is refused.

The fixed secrets that signed the committed fixtures are in `test/support/producers.ts`. They are test-only. A production or staging runtime refuses them.

ADR-026 requires a move to Ed25519 producer signatures before any non-shadow deployment. That change is separate and is not done.
