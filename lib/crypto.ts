const DB_NAME = "privchat-secure-vault";
const STORE_NAME = "device-keys";
const DB_VERSION = 2;
const ALGORITHM_V2 = "ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256" as const;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type DeviceKeyBundle = {
  version: 2;
  publicKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  privateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
  fingerprint: string;
  keySignature: string;
};

export type EnvelopeContext = {
  conversationId: string;
  senderId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  nonce: string;
};

export type EncryptedEnvelope = {
  ciphertext: string;
  iv: string;
  salt: string;
  ephemeral_public_key?: JsonWebKey | null;
  signature?: string | null;
  aad?: string | null;
  algorithm?: typeof ALGORITHM_V2 | "ECDH-P256/HKDF-SHA256/AES-256-GCM" | string;
};

export type PublishedDeviceKeys = {
  id: string;
  fingerprint: string;
  public_key: JsonWebKey;
  signing_public_key?: JsonWebKey | null;
  key_signature?: string | null;
};

type LegacyBundle = {
  publicKey?: JsonWebKey;
  privateKey?: JsonWebKey;
};

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function canonicalKey(key: JsonWebKey | null | undefined) {
  return {
    crv: key?.crv ?? "",
    kty: key?.kty ?? "",
    x: key?.x ?? "",
    y: key?.y ?? "",
  };
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function openVault(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function vaultGet<T>(key: string): Promise<T | undefined> {
  const db = await openVault();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function vaultSet<T>(key: string, value: T) {
  const db = await openVault();
  return new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function vaultDelete(key: string) {
  const db = await openVault();
  return new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).delete(key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function fingerprint(agreementKey: JsonWebKey, signingKey: JsonWebKey) {
  const digest = await sha256(stableStringify({ agreement: canonicalKey(agreementKey), signing: canonicalKey(signingKey) }));
  return digest.match(/.{1,4}/g)!.slice(0, 10).join(" ").toUpperCase();
}

function deviceBindingPayload(agreementKey: JsonWebKey, signingKey: JsonWebKey) {
  return stableStringify({ v: 2, agreement: canonicalKey(agreementKey), signing: canonicalKey(signingKey) });
}

async function generateSigningPair() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

async function generateAgreementPair() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  )) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

async function finishBundle(agreement: { privateKey: CryptoKey; publicKey: JsonWebKey }) {
  const signing = await generateSigningPair();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signing.privateKey,
    encoder.encode(deviceBindingPayload(agreement.publicKey, signing.publicKey)),
  );
  return {
    version: 2 as const,
    publicKey: agreement.publicKey,
    signingPublicKey: signing.publicKey,
    privateKey: agreement.privateKey,
    signingPrivateKey: signing.privateKey,
    fingerprint: await fingerprint(agreement.publicKey, signing.publicKey),
    keySignature: bytesToBase64(new Uint8Array(signature)),
  };
}

export async function ensureDeviceKeys(userId: string): Promise<DeviceKeyBundle> {
  if (!globalThis.isSecureContext || !crypto?.subtle || !globalThis.indexedDB) {
    throw new Error("secure_context_required");
  }
  const storageKey = `device:${userId}`;
  const existing = await vaultGet<DeviceKeyBundle | LegacyBundle>(storageKey);
  if (
    existing &&
    "version" in existing &&
    existing.version === 2 &&
    existing.privateKey instanceof CryptoKey &&
    existing.signingPrivateKey instanceof CryptoKey
  ) {
    return existing;
  }

  let agreement: { privateKey: CryptoKey; publicKey: JsonWebKey };
  if (existing?.privateKey && !(existing.privateKey instanceof CryptoKey) && existing.publicKey) {
    const migratedPrivateKey = await crypto.subtle.importKey(
      "jwk",
      existing.privateKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    agreement = { privateKey: migratedPrivateKey, publicKey: existing.publicKey };
  } else {
    agreement = await generateAgreementPair();
  }

  const bundle = await finishBundle(agreement);
  await vaultSet(storageKey, bundle);
  return bundle;
}

export async function removeDeviceKeys(userId: string) {
  await vaultDelete(`device:${userId}`);
}

export async function verifyDeviceRegistration(device: PublishedDeviceKeys) {
  if (!device.signing_public_key || !device.key_signature) return false;
  try {
    const signingKey = await crypto.subtle.importKey(
      "jwk",
      device.signing_public_key,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      arrayBuffer(base64ToBytes(device.key_signature)),
      encoder.encode(deviceBindingPayload(device.public_key, device.signing_public_key)),
    );
  } catch {
    return false;
  }
}

export async function checkTrustedDevice(device: PublishedDeviceKeys): Promise<"trusted" | "first_seen" | "changed" | "invalid"> {
  if (!(await verifyDeviceRegistration(device))) return "invalid";
  const trustKey = `trust:${device.id}`;
  const digest = await sha256(
    stableStringify({ agreement: canonicalKey(device.public_key), signing: canonicalKey(device.signing_public_key) }),
  );
  const existing = await vaultGet<string>(trustKey);
  if (!existing) {
    await vaultSet(trustKey, digest);
    return "first_seen";
  }
  return existing === digest ? "trusted" : "changed";
}

async function importAgreementPublic(publicJwk: JsonWebKey) {
  return crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

async function deriveAesKey(
  privateKey: CryptoKey,
  publicJwk: JsonWebKey,
  salt: Uint8Array,
  info: string,
) {
  const publicKey = await importAgreementPublic(publicJwk);
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: arrayBuffer(salt), info: encoder.encode(info) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function aadFor(context: EnvelopeContext) {
  return stableStringify({
    c: context.conversationId,
    n: context.nonce,
    rd: context.recipientDeviceId,
    s: context.senderId,
    sd: context.senderDeviceId,
    v: 2,
  });
}

function signaturePayload(envelope: EncryptedEnvelope) {
  return stableStringify({
    aad: envelope.aad,
    algorithm: envelope.algorithm,
    ciphertext: envelope.ciphertext,
    ephemeral: canonicalKey(envelope.ephemeral_public_key),
    iv: envelope.iv,
    salt: envelope.salt,
  });
}

export async function encryptMessage(
  plaintext: string,
  signingPrivateKey: CryptoKey,
  recipientPublicJwk: JsonWebKey,
  context: EnvelopeContext,
): Promise<EncryptedEnvelope> {
  const ephemeral = await generateAgreementPair();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const aad = aadFor(context);
  const key = await deriveAesKey(
    ephemeral.privateKey,
    recipientPublicJwk,
    salt,
    `privchat:v2:${context.conversationId}:${context.senderDeviceId}:${context.recipientDeviceId}`,
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: arrayBuffer(iv), additionalData: encoder.encode(aad), tagLength: 128 },
    key,
    encoder.encode(plaintext),
  );
  const envelope: EncryptedEnvelope = {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
    salt: bytesToBase64(salt),
    ephemeral_public_key: ephemeral.publicKey,
    aad,
    algorithm: ALGORITHM_V2,
  };
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingPrivateKey,
    encoder.encode(signaturePayload(envelope)),
  );
  envelope.signature = bytesToBase64(new Uint8Array(signature));
  return envelope;
}

function assertContext(aad: string, expected: EnvelopeContext) {
  const parsed = JSON.parse(aad) as Record<string, unknown>;
  if (
    parsed.v !== 2 ||
    parsed.c !== expected.conversationId ||
    parsed.s !== expected.senderId ||
    parsed.sd !== expected.senderDeviceId ||
    parsed.rd !== expected.recipientDeviceId ||
    parsed.n !== expected.nonce
  ) {
    throw new Error("context_mismatch");
  }
}

export async function decryptMessage(
  envelope: EncryptedEnvelope,
  ownPrivateKey: CryptoKey,
  senderAgreementPublicKey: JsonWebKey,
  senderSigningPublicKey: JsonWebKey | null | undefined,
  expected: EnvelopeContext,
) {
  if (envelope.ephemeral_public_key && envelope.signature && envelope.aad && senderSigningPublicKey) {
    assertContext(envelope.aad, expected);
    const signingKey = await crypto.subtle.importKey(
      "jwk",
      senderSigningPublicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      arrayBuffer(base64ToBytes(envelope.signature)),
      encoder.encode(signaturePayload(envelope)),
    );
    if (!valid) throw new Error("invalid_signature");
    const salt = base64ToBytes(envelope.salt);
    const key = await deriveAesKey(
      ownPrivateKey,
      envelope.ephemeral_public_key,
      salt,
      `privchat:v2:${expected.conversationId}:${expected.senderDeviceId}:${expected.recipientDeviceId}`,
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: arrayBuffer(base64ToBytes(envelope.iv)),
        additionalData: encoder.encode(envelope.aad),
        tagLength: 128,
      },
      key,
      arrayBuffer(base64ToBytes(envelope.ciphertext)),
    );
    return { plaintext: decoder.decode(plaintext), verified: true, legacy: false };
  }

  const salt = base64ToBytes(envelope.salt);
  const legacyKey = await deriveAesKey(
    ownPrivateKey,
    senderAgreementPublicKey,
    salt,
    `privchat:v1:${expected.conversationId}`,
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: arrayBuffer(base64ToBytes(envelope.iv)),
      additionalData: encoder.encode(expected.conversationId),
      tagLength: 128,
    },
    legacyKey,
    arrayBuffer(base64ToBytes(envelope.ciphertext)),
  );
  return { plaintext: decoder.decode(plaintext), verified: false, legacy: true };
}

export function encryptionLabel() {
  return "AES‑256‑GCM · Ephemeral ECDH · ECDSA";
}
