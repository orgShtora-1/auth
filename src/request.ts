export class RequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

export async function readJson(request: Request, maxBytes: number): Promise<unknown> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new RequestError(415, "unsupported_media_type");

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) throw new RequestError(400, "invalid_request");
    if (length > maxBytes) throw new RequestError(413, "request_too_large");
  }

  if (!request.body) throw new RequestError(400, "invalid_request");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new RequestError(413, "request_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new RequestError(400, "invalid_request");
  }
}

function objectFields(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RequestError(400, "invalid_request");
  }
  return value as Record<string, unknown>;
}

export function parseEmailRequest(value: unknown): string {
  return parseEmail(objectFields(value).email);
}

export function parseActionTokenRequest(value: unknown): string {
  return parseActionToken(objectFields(value).token);
}
export function parseEmail(value: unknown): string {
  if (typeof value !== "string" || value.length > 254 || !value.includes("@") || /\s/.test(value)) {
    throw new RequestError(400, "invalid_request");
  }
  return value.trim().toLowerCase();
}

export function parseActionToken(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new RequestError(400, "invalid_request");
  }
  return value;
}

function parsePassword(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new RequestError(400, "invalid_request");
  let codePoints = 0;
  for (const _character of value) {
    codePoints += 1;
    if (codePoints > 4096) throw new RequestError(400, "invalid_request");
  }
  return value;
}

function parseUsername(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{3,32}$/.test(value)) {
    throw new RequestError(400, "invalid_request");
  }
  return value.toLowerCase();
}

export function parseRegistrationCredentials(
  value: unknown,
  mode: "email" | "username" | "both" | "either",
): { email?: string; username?: string; password: string } {
  const fields = objectFields(value);
  const password = parsePassword(fields.password);
  const hasEmail = fields.email !== undefined;
  const hasUsername = fields.username !== undefined;
  if ((mode === "email" && (hasUsername || !hasEmail)) ||
      (mode === "username" && (hasEmail || !hasUsername)) ||
      (mode === "both" && (!hasEmail || !hasUsername)) ||
      (mode === "either" && hasEmail === hasUsername)) {
    throw new RequestError(400, "invalid_request");
  }
  const email = hasEmail ? parseEmail(fields.email) : undefined;
  const username = hasUsername ? parseUsername(fields.username) : undefined;
  return { ...(email === undefined ? {} : { email }), ...(username === undefined ? {} : { username }), password };
}

export function parseLoginCredentials(
  value: unknown,
  mode: "email" | "username" | "either",
): { identifier: { type: "email" | "username"; value: string }; password: string } {
  const fields = objectFields(value);
  const password = parsePassword(fields.password);
  const hasEmail = fields.email !== undefined;
  const hasUsername = fields.username !== undefined;
  if ((mode === "email" && (hasUsername || !hasEmail)) ||
      (mode === "username" && (hasEmail || !hasUsername)) ||
      (mode === "either" && hasEmail === hasUsername)) {
    throw new RequestError(400, "invalid_request");
  }
  return {
    identifier: hasEmail
      ? { type: "email", value: parseEmail(fields.email) }
      : { type: "username", value: parseUsername(fields.username) },
    password,
  };
}

export function parsePasswordReset(value: unknown): { token: string; password: string } {
  const { token, password } = objectFields(value);
  return { token: parseActionToken(token), password: parsePassword(password) };
}
