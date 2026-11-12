const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let output = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += base32Alphabet[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) output += base32Alphabet[(value << (5 - bits)) & 0x1f];
  return output;
}

export function base32Decode(encoded: string): Uint8Array {
  const clean = encoded.toUpperCase().replace(/[= -]/g, "");
  if (!/^[A-Z2-7]+$/.test(clean)) throw new TypeError("secret is not valid Base32");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const character of clean) {
    value = (value << 5) | base32Alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

export function createTotpSecret(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

const encoder = new TextEncoder();

async function hotp(secret: Uint8Array, counter: number, digits: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    secret as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, counterBytes as unknown as ArrayBuffer));
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

export interface TotpVerificationInput {
  secret: string;
  token: string;
  digits: number;
  periodSeconds: number;
  skew: number;
  nowMs: number;
}

/** Verifies an RFC 6238 code within the configured time-step drift. */
export async function verifyTotp(input: TotpVerificationInput): Promise<boolean> {
  if (!new RegExp(`^[0-9]{${input.digits}}$`).test(input.token)) return false;
  const secret = base32Decode(input.secret);
  const currentStep = Math.floor(input.nowMs / 1000 / input.periodSeconds);
  for (let drift = -input.skew; drift <= input.skew; drift += 1) {
    const step = currentStep + drift;
    if (step < 0) continue;
    const expected = await hotp(secret, step, input.digits);
    if (constantTimeEqual(input.token, expected)) return true;
  }
  return false;
}

export function createOtpauthUri(input: {
  issuer: string;
  accountLabel: string;
  secret: string;
  digits: number;
  periodSeconds: number;
}): string {
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.accountLabel)}`;
  const params = new URLSearchParams({
    secret: input.secret,
    issuer: input.issuer,
    algorithm: "SHA1",
    digits: String(input.digits),
    period: String(input.periodSeconds),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export function createRecoveryCodes(count: number): string[] {
  const codes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const bytes = new Uint8Array(7);
    globalThis.crypto.getRandomValues(bytes);
    const raw = base32Encode(bytes).slice(0, 10);
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

/** Normalizes user-typed recovery codes before hashing or comparison. */
export function normalizeRecoveryCode(value: string): string {
  return value.toUpperCase().replace(/[ -]/g, "");
}

export function totpCodeHashInput(code: string): Uint8Array {
  return encoder.encode(code);
}
