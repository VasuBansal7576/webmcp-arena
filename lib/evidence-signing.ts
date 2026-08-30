const ATTESTATION_KIND = "arena.evidence_attestation";
const ATTESTATION_VERSION = 1;
const ALGORITHM = "Ed25519";
const SIGNATURE_DOMAIN = "arena.evidence-attestation.v1\0";
const PUBLIC_JWK_FIELDS = ["alg", "crv", "ext", "key_ops", "kty", "x"];
const ATTESTATION_FIELDS = [
  "algorithm",
  "issuedAt",
  "keyId",
  "keySource",
  "kind",
  "payloadHash",
  "publicKey",
  "signature",
  "version",
];

export type EvidenceSigningEnvironment = {
  ARENA_SIGNING_PRIVATE_JWK?: string;
  ARENA_SIGNING_PUBLIC_JWK?: string;
  ARENA_ALLOW_EPHEMERAL_SIGNING?: string;
};

type KeySource = "configured" | "ephemeral_development";

type AttestationStatement = {
  kind: typeof ATTESTATION_KIND;
  version: typeof ATTESTATION_VERSION;
  algorithm: typeof ALGORITHM;
  payloadHash: string;
  keyId: string;
  issuedAt: string;
  keySource: KeySource;
};

type SigningMaterial = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JsonWebKey;
  keySource: KeySource;
};

export async function signEvidence(bundle: unknown, payloadHash: string) {
  return signEvidenceWithEnvironment(bundle, payloadHash, {
    ARENA_SIGNING_PRIVATE_JWK: process.env.ARENA_SIGNING_PRIVATE_JWK,
    ARENA_SIGNING_PUBLIC_JWK: process.env.ARENA_SIGNING_PUBLIC_JWK,
    ARENA_ALLOW_EPHEMERAL_SIGNING: process.env.ARENA_ALLOW_EPHEMERAL_SIGNING,
  });
}

export async function signEvidenceWithEnvironment(
  bundle: unknown,
  payloadHash: string,
  environment: EvidenceSigningEnvironment,
  issuedAt = new Date(),
) {
  const expectedPayloadHash = await hashCanonicalValue(bundle);
  if (!sameBase64Url(payloadHash, expectedPayloadHash, 32)) {
    throw new Error("Arena evidence payload hash does not match the bundle");
  }
  if (!(issuedAt instanceof Date) || !Number.isFinite(issuedAt.getTime())) {
    throw new Error("Arena evidence issuedAt must be a valid Date");
  }

  const material = await loadSigningMaterial(environment);
  const statement: AttestationStatement = {
    kind: ATTESTATION_KIND,
    version: ATTESTATION_VERSION,
    algorithm: ALGORITHM,
    payloadHash,
    keyId: await createKeyId(material.publicJwk),
    issuedAt: issuedAt.toISOString(),
    keySource: material.keySource,
  };
  const message = attestationMessage(statement);
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign({ name: ALGORITHM }, material.privateKey, message),
  );
  const pairMatches = await crypto.subtle.verify(
    { name: ALGORITHM },
    material.publicKey,
    signatureBytes,
    message,
  );
  if (!pairMatches) throw new Error("Arena signing key pair does not match");

  return {
    ...statement,
    signature: toBase64Url(signatureBytes),
    publicKey: material.publicJwk,
  };
}

export async function verifyEvidenceAttestation(
  bundle: unknown,
  candidate: unknown,
  trustedPublicJwk: unknown,
) {
  try {
    if (!isRecord(candidate) || !hasOnlyKeys(candidate, ATTESTATION_FIELDS)) return false;
    if (!isRecord(candidate.publicKey) || !isRecord(trustedPublicJwk)) return false;
    if (!hasOnlyKeys(candidate.publicKey, PUBLIC_JWK_FIELDS)) return false;

    const embeddedPublicJwk = normalizePublicJwk(candidate.publicKey);
    const trustedPublicKeyJwk = normalizePublicJwk(trustedPublicJwk);
    if (canonicalJson(embeddedPublicJwk) !== canonicalJson(trustedPublicKeyJwk)) return false;
    if (canonicalJson(candidate.publicKey) !== canonicalJson(embeddedPublicJwk)) return false;

    const statement = parseAttestationStatement(candidate);
    if (!statement) return false;
    const expectedPayloadHash = await hashCanonicalValue(bundle);
    if (!sameBase64Url(statement.payloadHash, expectedPayloadHash, 32)) return false;
    if (statement.keyId !== await createKeyId(trustedPublicKeyJwk)) return false;

    const signature = decodeBase64Url(candidate.signature, 64);
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      trustedPublicKeyJwk,
      { name: ALGORITHM },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: ALGORITHM },
      publicKey,
      signature,
      attestationMessage(statement),
    );
  } catch {
    return false;
  }
}

async function loadSigningMaterial(environment: EvidenceSigningEnvironment): Promise<SigningMaterial> {
  const privateJwkJson = configuredValue(environment.ARENA_SIGNING_PRIVATE_JWK);
  const publicJwkJson = configuredValue(environment.ARENA_SIGNING_PUBLIC_JWK);
  if (Boolean(privateJwkJson) !== Boolean(publicJwkJson)) {
    throw new Error("Arena requires both signing keys when either is configured");
  }

  if (privateJwkJson && publicJwkJson) {
    const privateJwk = normalizePrivateJwk(parseJwk(privateJwkJson, "private"));
    const publicJwk = normalizePublicJwk(parseJwk(publicJwkJson, "public"));
    const [privateKey, publicKey] = await Promise.all([
      crypto.subtle.importKey("jwk", privateJwk, { name: ALGORITHM }, false, ["sign"]),
      crypto.subtle.importKey("jwk", publicJwk, { name: ALGORITHM }, false, ["verify"]),
    ]);
    return { privateKey, publicKey, publicJwk, keySource: "configured" };
  }

  if (environment.ARENA_ALLOW_EPHEMERAL_SIGNING !== "true") {
    throw new Error("Arena signing keys are not configured");
  }
  const generated = await crypto.subtle.generateKey(
    { name: ALGORITHM },
    true,
    ["sign", "verify"],
  );
  if (!("privateKey" in generated)) throw new Error("Arena could not generate an Ed25519 signing key pair");
  const exportedPublicJwk = await crypto.subtle.exportKey("jwk", generated.publicKey);
  return {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey,
    publicJwk: normalizePublicJwk(exportedPublicJwk),
    keySource: "ephemeral_development",
  };
}

function parseAttestationStatement(candidate: Record<string, unknown>): AttestationStatement | null {
  if (
    candidate.kind !== ATTESTATION_KIND
    || candidate.version !== ATTESTATION_VERSION
    || candidate.algorithm !== ALGORITHM
    || typeof candidate.payloadHash !== "string"
    || typeof candidate.keyId !== "string"
    || typeof candidate.issuedAt !== "string"
    || (candidate.keySource !== "configured" && candidate.keySource !== "ephemeral_development")
    || typeof candidate.signature !== "string"
  ) return null;
  const parsedIssuedAt = Date.parse(candidate.issuedAt);
  if (!Number.isFinite(parsedIssuedAt) || new Date(parsedIssuedAt).toISOString() !== candidate.issuedAt) return null;
  decodeBase64Url(candidate.payloadHash, 32);
  if (!/^ed25519:[A-Za-z0-9_-]{43}$/.test(candidate.keyId)) return null;
  return {
    kind: candidate.kind,
    version: candidate.version,
    algorithm: candidate.algorithm,
    payloadHash: candidate.payloadHash,
    keyId: candidate.keyId,
    issuedAt: candidate.issuedAt,
    keySource: candidate.keySource,
  };
}

function parseJwk(value: string, label: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`Arena ${label} signing key must be a JSON Web Key`);
  }
  if (!isRecord(parsed)) throw new Error(`Arena ${label} signing key must be a JSON Web Key`);
  return parsed;
}

function normalizePrivateJwk(candidate: unknown): JsonWebKey {
  if (!isRecord(candidate)) throw new Error("Arena private signing key must be an Ed25519 JWK");
  const x = requireEd25519Coordinate(candidate, "x", "private");
  const d = requireEd25519Coordinate(candidate, "d", "private");
  return {
    kty: "OKP",
    crv: "Ed25519",
    x,
    d,
    alg: "EdDSA",
    ext: false,
    key_ops: ["sign"],
  };
}

function normalizePublicJwk(candidate: unknown): JsonWebKey {
  if (!isRecord(candidate)) throw new Error("Arena public signing key must be an Ed25519 JWK");
  const x = requireEd25519Coordinate(candidate, "x", "public");
  return {
    kty: "OKP",
    crv: "Ed25519",
    x,
    alg: "EdDSA",
    ext: true,
    key_ops: ["verify"],
  };
}

function requireEd25519Coordinate(
  candidate: Record<string, unknown>,
  field: "x" | "d",
  label: string,
) {
  if (candidate.kty !== "OKP" || candidate.crv !== "Ed25519" || typeof candidate[field] !== "string") {
    throw new Error(`Arena ${label} signing key must be an Ed25519 JWK`);
  }
  decodeBase64Url(candidate[field], 32);
  return candidate[field];
}

function attestationMessage(statement: AttestationStatement) {
  return new TextEncoder().encode(`${SIGNATURE_DOMAIN}${canonicalJson(statement)}`);
}

async function createKeyId(publicJwk: JsonWebKey) {
  return `ed25519:${await hashCanonicalValue(publicJwk)}`;
}

async function hashCanonicalValue(value: unknown) {
  const serialized = canonicalJson(value);
  if (typeof serialized !== "string") throw new Error("Arena evidence must be canonical JSON");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serialized));
  return toBase64Url(new Uint8Array(digest));
}

function configuredValue(value: string | undefined) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function sameBase64Url(left: string, right: string, expectedBytes: number) {
  try {
    const leftBytes = decodeBase64Url(left, expectedBytes);
    const rightBytes = decodeBase64Url(right, expectedBytes);
    let difference = 0;
    for (let index = 0; index < expectedBytes; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
    return difference === 0;
  } catch {
    return false;
  }
}

function decodeBase64Url(value: unknown, expectedBytes: number) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Arena evidence contains invalid base64url data");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Arena evidence contains invalid base64url data");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== expectedBytes || toBase64Url(bytes) !== value) {
    throw new Error("Arena evidence contains invalid base64url data");
  }
  return bytes;
}

function toBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function hasOnlyKeys(candidate: Record<string, unknown>, expected: string[]) {
  const actual = Object.keys(candidate).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Arena canonical JSON supports only finite JSON values");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
