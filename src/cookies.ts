const tokenPattern = /^[a-f0-9]{64}$/;

export function readSessionToken(cookieHeader: string | null, cookieName: string): string | null {
  if (!cookieHeader || cookieHeader.length > 16_384) return null;

  let token: string | null = null;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== cookieName) continue;
    if (token !== null) return null;

    const value = part.slice(separator + 1).trim();
    if (!tokenPattern.test(value)) return null;
    token = value;
  }

  return token;
}

export function sessionCookie(token: string, cookieName: string, ttlSeconds: number, now: number): string {
  const expires = new Date(now + ttlSeconds * 1000).toUTCString();
  return `${cookieName}=${token}; Max-Age=${ttlSeconds}; Expires=${expires}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

export function clearedSessionCookie(cookieName: string): string {
  return `${cookieName}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
