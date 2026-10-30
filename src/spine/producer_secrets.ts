import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { ENVIRONMENTS, type Environment } from "../contracts/envelope.js";
import type { ProducerRegistration } from "./producers.js";

/**
 * Producer secrets come from protected configuration, never from source
 * (KI-SENTINEL-20261030-002). The source holds only the non-secret producer
 * profiles; each environment supplies its own key ids and secrets in a file
 * named by SENTINEL_PRODUCER_SECRETS_FILE.
 */
export const PRODUCER_SECRETS_FILE_ENV = "SENTINEL_PRODUCER_SECRETS_FILE";
export const PRODUCER_SECRETS_SCHEMA = "forgesentinel.producer_secrets.v1";
export const MIN_PRODUCER_SECRET_BYTES = 32;
/** Fewest distinct characters a protected-environment secret may have. A random 32-byte hex secret has 16. */
export const MIN_PRODUCER_SECRET_DISTINCT_CHARS = 10;
/** Printable ASCII with no space: the only characters a protected-environment secret may use. */
const PROTECTED_SECRET_PATTERN = /^[!-~]+$/;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
/** Prefix of the fixed fixture secrets published in git history before this change. */
export const PUBLISHED_TEST_SECRET_PREFIX = "test-secret-";
/** Environments where a weak or published producer secret is refused. */
export const PROTECTED_ENVIRONMENTS: readonly Environment[] = ["production", "staging"];

export type ProducerProfile = Omit<ProducerRegistration, "environment" | "key_id" | "secret">;

export const STANDARD_PRODUCER_PROFILES: readonly ProducerProfile[] = [
  { service: "identity-service", signature_required: false, allowed_event_prefixes: ["identity."], tenant_scope: "required" },
  { service: "usage-metering", signature_required: false, allowed_event_prefixes: ["usage."], tenant_scope: "required" },
  { service: "neuroforge", signature_required: false, allowed_event_prefixes: ["neuroforge."], tenant_scope: "required" },
  { service: "billing-service", signature_required: true, allowed_event_prefixes: ["billing.", "license."], tenant_scope: "required" },
  { service: "cssa", signature_required: true, allowed_event_prefixes: ["cssa."], tenant_scope: "required" },
  { service: "forgeagents", signature_required: false, allowed_event_prefixes: ["agent.", "data."], tenant_scope: "required" },
];

/** A configuration error. Its message never contains a secret value. */
export class ProducerSecretsError extends Error {
  override readonly name = "ProducerSecretsError";
}

export function isProtectedEnvironment(environment: Environment): boolean {
  return PROTECTED_ENVIRONMENTS.includes(environment);
}

/**
 * Refuse producer registrations that a runtime in `environment` must not use.
 * Every environment: the registration environment matches and the key id and
 * secret are present. Production and staging also refuse published test
 * secrets, short secrets, and one secret shared by two producers.
 */
export function assertProducerSecretsAllowed(environment: Environment, registrations: readonly ProducerRegistration[]): void {
  const seen = new Map<string, string>();
  for (const registration of registrations) {
    const who = `producer "${registration.service}"`;
    if (registration.environment !== environment) {
      throw new ProducerSecretsError(`${who} is registered for "${registration.environment}", not "${environment}"`);
    }
    if (typeof registration.key_id !== "string" || registration.key_id.length === 0) {
      throw new ProducerSecretsError(`${who} has no key_id`);
    }
    if (typeof registration.secret !== "string" || registration.secret.length === 0) {
      throw new ProducerSecretsError(`${who} has no secret`);
    }
    // HMAC pads a short key with NUL bytes, so a secret of NUL bytes is the
    // empty key. Control characters are refused in every environment.
    if (CONTROL_CHARACTER.test(registration.secret)) {
      throw new ProducerSecretsError(`${who} secret contains a control character`);
    }
    if (!isProtectedEnvironment(environment)) continue;
    if (registration.secret.startsWith(PUBLISHED_TEST_SECRET_PREFIX)) {
      throw new ProducerSecretsError(`${who} uses a published test secret; "${environment}" refuses it`);
    }
    if (!PROTECTED_SECRET_PATTERN.test(registration.secret)) {
      throw new ProducerSecretsError(`${who} secret must use printable ASCII with no spaces; "${environment}" refuses it`);
    }
    if (registration.secret.length < MIN_PRODUCER_SECRET_BYTES) {
      throw new ProducerSecretsError(`${who} secret is shorter than ${MIN_PRODUCER_SECRET_BYTES} bytes; "${environment}" refuses it`);
    }
    if (new Set(registration.secret).size < MIN_PRODUCER_SECRET_DISTINCT_CHARS) {
      throw new ProducerSecretsError(`${who} secret has fewer than ${MIN_PRODUCER_SECRET_DISTINCT_CHARS} distinct characters; "${environment}" refuses it`);
    }
    const other = seen.get(registration.secret);
    if (other !== undefined) {
      throw new ProducerSecretsError(`${who} shares its secret with producer "${other}"; "${environment}" refuses it`);
    }
    seen.set(registration.secret, registration.service);
  }
}

const TOP_LEVEL_FIELDS: readonly string[] = ["schema", "environment", "producers"];
const ENTRY_FIELDS: readonly string[] = ["key_id", "secret"];

export interface LoadProducerSecretsOptions {
  /** Defaults to process.env. */
  env?: Readonly<Record<string, string | undefined>>;
  /** Defaults to process.platform. The file-permission check is POSIX only. */
  platform?: NodeJS.Platform;
}

/**
 * Load the standard producer registrations for `environment` from the
 * protected secrets file. Fails closed: a missing variable; a file that is a
 * symlink, not a regular file, unreadable, or (POSIX) group/world-accessible
 * or owned by another user; a different environment; an unknown field; a
 * missing or unknown producer; a shared key_id; or a refused secret throws
 * ProducerSecretsError. On Windows, symlinks are followed and there is no
 * permission or owner check.
 */
export function loadProducerRegistrations(environment: Environment, options: LoadProducerSecretsOptions = {}): ProducerRegistration[] {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const path = env[PRODUCER_SECRETS_FILE_ENV];
  if (!path) {
    throw new ProducerSecretsError(`${PRODUCER_SECRETS_FILE_ENV} is not set; producer secrets have no built-in default`);
  }

  // Open once and check the open descriptor, so the file checked is the file
  // read. O_NOFOLLOW refuses a symlink and O_NONBLOCK keeps a FIFO from
  // blocking the open (POSIX). fstat then refuses anything but a regular file.
  const posix = platform !== "win32";
  const flags = constants.O_RDONLY | (posix ? (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0) : 0);
  let content: string;
  let fd: number | undefined;
  try {
    try {
      fd = openSync(path, flags);
    } catch {
      throw new ProducerSecretsError(`cannot open the producer secrets file named by ${PRODUCER_SECRETS_FILE_ENV} (a symlink is refused)`);
    }
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new ProducerSecretsError("the producer secrets file must be a regular file");
    }
    if (posix && (stat.mode & 0o077) !== 0) {
      throw new ProducerSecretsError(`the producer secrets file must not be readable or writable by group or others (mode ${(stat.mode & 0o777).toString(8)})`);
    }
    const uid = process.getuid?.();
    if (posix && uid !== undefined && stat.uid !== uid) {
      throw new ProducerSecretsError("the producer secrets file must be owned by the user that runs Sentinel");
    }
    try {
      content = readFileSync(fd, "utf8");
    } catch {
      throw new ProducerSecretsError(`cannot read the producer secrets file named by ${PRODUCER_SECRETS_FILE_ENV}`);
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  let document: unknown;
  try {
    document = JSON.parse(content);
  } catch {
    throw new ProducerSecretsError("the producer secrets file is not valid JSON");
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    throw new ProducerSecretsError("the producer secrets file must hold a JSON object");
  }
  const record = document as Record<string, unknown>;
  for (const field of Object.keys(record)) {
    if (!TOP_LEVEL_FIELDS.includes(field)) throw new ProducerSecretsError(`the producer secrets file has unknown field "${field}"`);
  }
  if (record["schema"] !== PRODUCER_SECRETS_SCHEMA) {
    throw new ProducerSecretsError(`the producer secrets file schema must be "${PRODUCER_SECRETS_SCHEMA}"`);
  }
  if (typeof record["environment"] !== "string" || !(ENVIRONMENTS as readonly string[]).includes(record["environment"])) {
    throw new ProducerSecretsError("the producer secrets file has no valid environment");
  }
  if (record["environment"] !== environment) {
    throw new ProducerSecretsError(`the producer secrets file is for "${record["environment"]}", not "${environment}"`);
  }
  const producers = record["producers"];
  if (typeof producers !== "object" || producers === null || Array.isArray(producers)) {
    throw new ProducerSecretsError("the producer secrets file has no producers object");
  }
  const entries = producers as Record<string, unknown>;

  const known = new Set(STANDARD_PRODUCER_PROFILES.map((profile) => profile.service));
  for (const service of Object.keys(entries)) {
    if (!known.has(service)) throw new ProducerSecretsError(`the producer secrets file names unknown producer "${service}"`);
  }

  const registrations = STANDARD_PRODUCER_PROFILES.map((profile): ProducerRegistration => {
    const entry = entries[profile.service];
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new ProducerSecretsError(`the producer secrets file has no entry for producer "${profile.service}"`);
    }
    for (const field of Object.keys(entry)) {
      if (!ENTRY_FIELDS.includes(field)) throw new ProducerSecretsError(`producer "${profile.service}" has unknown field "${field}"`);
    }
    const { key_id, secret } = entry as Record<string, unknown>;
    if (typeof key_id !== "string" || typeof secret !== "string") {
      throw new ProducerSecretsError(`producer "${profile.service}" needs string key_id and secret`);
    }
    return { ...profile, allowed_event_prefixes: [...profile.allowed_event_prefixes], environment, key_id, secret };
  });
  const keyIds = new Set<string>();
  for (const registration of registrations) {
    if (keyIds.has(registration.key_id)) throw new ProducerSecretsError(`key_id "${registration.key_id}" is used by more than one producer`);
    keyIds.add(registration.key_id);
  }
  assertProducerSecretsAllowed(environment, registrations);
  return registrations;
}
