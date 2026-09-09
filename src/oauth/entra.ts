/**
 * Minimal Entra ID (Azure AD) OIDC login for the /login step: builds the
 * redirect to Microsoft's sign-in page, exchanges the returned code for an
 * ID token, and verifies that token's signature and claims. Used in place
 * of the password prompt (src/oauth/login-router.ts) when
 * MCP_OAUTH_ENTRA_TENANT_ID/CLIENT_ID/CLIENT_SECRET are configured — see
 * src/oauth/entra-login-router.ts for the routes that call this.
 *
 * Deliberately hand-rolled with node:crypto instead of a JWT library: this
 * repo compiles to CommonJS, and jose (the obvious choice) dropped CJS
 * support in v5. RS256 verification against a JWKS is a well-defined,
 * bounded amount of code — see verifyIdToken below — so it's not worth
 * pinning to an old major version or fighting module formats for it.
 *
 * This module verifies who signed in (Entra proves identity). It does NOT
 * decide who is allowed to use this server — that's the allowlist check in
 * entra-login-router.ts, kept separate on purpose: anyone in the tenant can
 * sign in, but only allowlisted UPNs should get a CIPP-scoped MCP token.
 */
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  publicUrl: string;
}

export function getEntraRedirectUri(config: EntraConfig): string {
  return new URL('/oauth/entra/callback', config.publicUrl).href;
}

export function generateNonce(): string {
  return Buffer.from(randomBytes(24)).toString('base64url');
}

export function buildEntraAuthorizeUrl(config: EntraConfig, opts: { state: string; nonce: string }): string {
  const url = new URL(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize`);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', getEntraRedirectUri(config));
  url.searchParams.set('response_mode', 'query');
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', opts.state);
  url.searchParams.set('nonce', opts.nonce);
  return url.href;
}

interface EntraTokenErrorResponse {
  error: string;
  error_description?: string;
}

export async function exchangeEntraCode(config: EntraConfig, code: string): Promise<string> {
  const res = await fetch(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: getEntraRedirectUri(config),
    }),
  });

  const body = (await res.json()) as { id_token?: string } & Partial<EntraTokenErrorResponse>;
  if (!res.ok || !body.id_token) {
    const reason = body.error_description || body.error || `HTTP ${res.status}`;
    throw new Error(`Entra token exchange failed: ${reason}`);
  }
  return body.id_token;
}

interface JsonWebKey {
  kid: string;
  kty: string;
  n: string;
  e: string;
}

let jwksCache: { tenantId: string; keys: JsonWebKey[]; fetchedAt: number } | undefined;
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;

async function getEntraJwks(tenantId: string): Promise<JsonWebKey[]> {
  if (jwksCache && jwksCache.tenantId === tenantId && Date.now() - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    return jwksCache.keys;
  }
  const res = await fetch(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`);
  if (!res.ok) throw new Error(`Failed to fetch Entra JWKS: HTTP ${res.status}`);
  const body = (await res.json()) as { keys: JsonWebKey[] };
  jwksCache = { tenantId, keys: body.keys, fetchedAt: Date.now() };
  return body.keys;
}

function base64urlDecode(input: string): Buffer {
  return Buffer.from(input, 'base64url');
}

export interface VerifiedEntraIdentity {
  upn: string;
  claims: Record<string, unknown>;
}

/**
 * Verifies an Entra v2.0 ID token: RS256 signature against the tenant's
 * published JWKS, issuer, audience, expiry, and the OIDC nonce set when
 * this login started. Throws on any failure — never returns a "maybe".
 */
export async function verifyEntraIdToken(
  config: EntraConfig,
  idToken: string,
  expectedNonce: string
): Promise<VerifiedEntraIdentity> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed ID token');
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = JSON.parse(base64urlDecode(headerB64).toString('utf8')) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256' || !header.kid) {
    throw new Error(`Unsupported or missing ID token algorithm/kid: ${header.alg}`);
  }

  const keys = await getEntraJwks(config.tenantId);
  const jwk = keys.find((k) => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) throw new Error('No matching signing key found in Entra JWKS');

  const publicKey = createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = base64urlDecode(signatureB64);
  if (!cryptoVerify('RSA-SHA256', signingInput, publicKey, signature)) {
    throw new Error('ID token signature verification failed');
  }

  const claims = JSON.parse(base64urlDecode(payloadB64).toString('utf8')) as Record<string, unknown>;

  const expectedIssuer = `https://login.microsoftonline.com/${config.tenantId}/v2.0`;
  if (claims.iss !== expectedIssuer) {
    throw new Error(`Unexpected ID token issuer: ${String(claims.iss)}`);
  }
  if (claims.aud !== config.clientId) {
    throw new Error('Unexpected ID token audience');
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp < nowSeconds) {
    throw new Error('ID token is expired');
  }
  if (typeof claims.nbf === 'number' && claims.nbf > nowSeconds) {
    throw new Error('ID token is not yet valid');
  }
  const nonceClaim = typeof claims.nonce === 'string' ? claims.nonce : '';
  const nonceHash = createHash('sha256').update(nonceClaim).digest();
  const expectedHash = createHash('sha256').update(expectedNonce).digest();
  if (nonceHash.length !== expectedHash.length || !timingSafeEqual(nonceHash, expectedHash)) {
    throw new Error('ID token nonce does not match this login attempt');
  }

  const upn =
    (typeof claims.preferred_username === 'string' && claims.preferred_username) ||
    (typeof claims.email === 'string' && claims.email) ||
    (typeof claims.upn === 'string' && claims.upn) ||
    '';
  if (!upn) throw new Error('ID token has no usable identity claim (preferred_username/email/upn)');

  return { upn, claims };
}
