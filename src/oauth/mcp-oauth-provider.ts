/**
 * Self-issued OAuth 2.1 authorization server for the /mcp endpoint, sized for
 * a single authorized human clicking through Claude Desktop's connector
 * setup — not a general-purpose multi-tenant IdP.
 *
 * Why self-issued rather than delegating login to Entra ID: Claude Desktop's
 * connector flow performs RFC 7591 dynamic client registration against
 * whatever authorization server this server's metadata advertises. Entra ID
 * doesn't support open DCR, so delegating to it would still require this
 * server to sit in front and handle DCR itself — Entra would only replace
 * the password check below with an extra network hop, for a server that has
 * exactly one legitimate user.
 *
 * Why stateless tokens: Railway redeploys wipe process memory, and this
 * service has no database. Rather than accept "re-login after every
 * deploy", every issued client_id/access_token/refresh_token is a small
 * JSON payload plus an HMAC-SHA256 signature (keyed by
 * MCP_OAUTH_SIGNING_SECRET), verified on each use instead of looked up in
 * storage. As long as the signing secret stays the same Railway env var
 * across deploys, previously-registered clients and previously-issued
 * tokens keep working with no persistence layer. Rotating the secret
 * invalidates all of them at once — that's the revocation story.
 *
 * The one piece that *is* kept in memory is the login ticket / authorization
 * code used during the few seconds of the interactive password prompt.
 * Codes are single-use and expire in minutes by design, so statelessness
 * there buys nothing, and a restart mid-login just means retrying.
 */
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60; // 1 hour
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 180; // 180 days
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const LOGIN_TICKET_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_LOGIN_ATTEMPTS = 5;

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function sign(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

/** Packs a JSON payload into `<base64url payload>.<base64url hmac>`, verifiable without storage. */
function packSigned(secret: string, payload: unknown): string {
  const body = base64url(JSON.stringify(payload));
  return `${body}.${sign(secret, body)}`;
}

function unpackSigned<T>(secret: string, token: string): T | undefined {
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return undefined;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!sig || !timingSafeEqualStr(sign(secret, body), sig)) return undefined;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T;
  } catch {
    return undefined;
  }
}

interface ClientPayload {
  redirect_uris: string[];
  client_name?: string;
}

interface AccessTokenPayload {
  cid: string;
  exp: number;
  typ: 'access';
}

interface RefreshTokenPayload {
  cid: string;
  exp: number;
  typ: 'refresh';
}

interface PendingAuth {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
  attempts: number;
  expiresAt: number;
}

interface AuthCodeRecord {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  expiresAt: number;
}

export type LoginResult = { redirectUrl: string } | { error: string };

export interface McpOAuthProvider extends OAuthServerProvider {
  getLoginTicket(ticketId: string): PendingAuth | undefined;
  submitLogin(ticketId: string, password: string): LoginResult;
  /**
   * Completes a pending login without a password check, for callers that
   * already authenticated the human some other way (e.g. an Entra ID
   * sign-in plus allowlist check) and just need the ticket turned into an
   * authorization code.
   */
  completeLogin(ticketId: string): LoginResult;
}

export function createMcpOAuthProvider(options: { password: string; signingSecret: string }): McpOAuthProvider {
  const { password, signingSecret } = options;

  const pendingAuth = new Map<string, PendingAuth>();
  const authCodes = new Map<string, AuthCodeRecord>();

  function sweepExpired(): void {
    const now = Date.now();
    for (const [id, p] of pendingAuth) if (p.expiresAt < now) pendingAuth.delete(id);
    for (const [code, c] of authCodes) if (c.expiresAt < now) authCodes.delete(code);
  }

  function issueTokens(clientId: string): OAuthTokens {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = packSigned(signingSecret, {
      cid: clientId,
      exp: now + ACCESS_TOKEN_TTL_SECONDS,
      typ: 'access',
    } satisfies AccessTokenPayload);
    const refreshToken = packSigned(signingSecret, {
      cid: clientId,
      exp: now + REFRESH_TOKEN_TTL_SECONDS,
      typ: 'refresh',
    } satisfies RefreshTokenPayload);
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
    };
  }

  function mintAuthorizationCode(pending: PendingAuth): LoginResult {
    const code = base64url(randomBytes(32));
    authCodes.set(code, {
      clientId: pending.client.client_id,
      codeChallenge: pending.params.codeChallenge,
      redirectUri: pending.params.redirectUri,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });

    const redirectUrl = new URL(pending.params.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (pending.params.state !== undefined) redirectUrl.searchParams.set('state', pending.params.state);
    return { redirectUrl: redirectUrl.href };
  }

  const clientsStore: OAuthRegisteredClientsStore = {
    getClient(clientId: string): OAuthClientInformationFull | undefined {
      const payload = unpackSigned<ClientPayload>(signingSecret, clientId);
      if (!payload) return undefined;
      return {
        client_id: clientId,
        redirect_uris: payload.redirect_uris,
        client_name: payload.client_name,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      };
    },
    registerClient(client: OAuthClientMetadata): OAuthClientInformationFull {
      // Every registered client is treated as a public PKCE client: MCP's
      // authorization flow requires PKCE regardless, so a client_secret
      // would be dead weight this server would otherwise have to store and
      // check. Ignore whatever auth method was requested and never mint one.
      const payload: ClientPayload = {
        redirect_uris: client.redirect_uris,
        client_name: client.client_name,
      };
      return {
        redirect_uris: client.redirect_uris,
        client_name: client.client_name,
        grant_types: client.grant_types ?? ['authorization_code', 'refresh_token'],
        response_types: client.response_types ?? ['code'],
        scope: client.scope,
        token_endpoint_auth_method: 'none',
        client_id: packSigned(signingSecret, payload),
        client_id_issued_at: Math.floor(Date.now() / 1000),
      };
    },
  };

  return {
    get clientsStore() {
      return clientsStore;
    },

    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
      sweepExpired();
      const ticketId = base64url(randomBytes(24));
      pendingAuth.set(ticketId, { client, params, attempts: 0, expiresAt: Date.now() + LOGIN_TICKET_TTL_MS });
      res.redirect(302, `/login?ticket=${encodeURIComponent(ticketId)}`);
    },

    getLoginTicket(ticketId: string): PendingAuth | undefined {
      sweepExpired();
      return pendingAuth.get(ticketId);
    },

    submitLogin(ticketId: string, submittedPassword: string): LoginResult {
      sweepExpired();
      const pending = pendingAuth.get(ticketId);
      if (!pending) {
        return { error: 'This login link has expired. Go back to Claude and try connecting again.' };
      }

      if (!timingSafeEqualStr(submittedPassword, password)) {
        pending.attempts += 1;
        if (pending.attempts >= MAX_LOGIN_ATTEMPTS) {
          pendingAuth.delete(ticketId);
          return { error: 'Too many incorrect attempts. Go back to Claude and try connecting again.' };
        }
        return { error: 'Incorrect password.' };
      }

      pendingAuth.delete(ticketId);
      return mintAuthorizationCode(pending);
    },

    completeLogin(ticketId: string): LoginResult {
      sweepExpired();
      const pending = pendingAuth.get(ticketId);
      if (!pending) {
        return { error: 'This login link has expired. Go back to Claude and try connecting again.' };
      }
      pendingAuth.delete(ticketId);
      return mintAuthorizationCode(pending);
    },

    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
      const record = authCodes.get(authorizationCode);
      if (!record || record.expiresAt < Date.now() || record.clientId !== client.client_id) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      return record.codeChallenge;
    },

    async exchangeAuthorizationCode(
      client: OAuthClientInformationFull,
      authorizationCode: string,
      _codeVerifier?: string,
      redirectUri?: string
    ): Promise<OAuthTokens> {
      const record = authCodes.get(authorizationCode);
      if (!record || record.expiresAt < Date.now() || record.clientId !== client.client_id) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      if (redirectUri !== undefined && redirectUri !== record.redirectUri) {
        throw new InvalidGrantError('redirect_uri does not match the authorization request');
      }
      authCodes.delete(authorizationCode); // single use
      return issueTokens(client.client_id);
    },

    async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
      const payload = unpackSigned<RefreshTokenPayload>(signingSecret, refreshToken);
      const nowSeconds = Math.floor(Date.now() / 1000);
      if (!payload || payload.typ !== 'refresh' || payload.exp < nowSeconds || payload.cid !== client.client_id) {
        throw new InvalidGrantError('Invalid or expired refresh token');
      }
      return issueTokens(client.client_id);
    },

    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const payload = unpackSigned<AccessTokenPayload>(signingSecret, token);
      const nowSeconds = Math.floor(Date.now() / 1000);
      if (!payload || payload.typ !== 'access' || payload.exp < nowSeconds) {
        throw new InvalidTokenError('Invalid or expired access token');
      }
      return { token, clientId: payload.cid, scopes: [], expiresAt: payload.exp };
    },
  };
}
