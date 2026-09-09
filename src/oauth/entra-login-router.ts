/**
 * Routes used when Entra ID login is configured, mounted in place of
 * src/oauth/login-router.ts's password form. `/login` hands off to
 * Microsoft's sign-in page instead of rendering a form; `/oauth/entra/callback`
 * receives Entra's redirect back, verifies the ID token, checks the signed-in
 * user against the allowlist, and — only then — completes the pending MCP
 * login exactly like the password path would have.
 *
 * The two routers are built together because the nonce minted for a ticket
 * at /login has to be read back for that same ticket at /callback.
 */
import express, { Router } from 'express';
import type { Logger } from '../utils/logger.js';
import type { McpOAuthProvider } from './mcp-oauth-provider.js';
import { buildEntraAuthorizeUrl, exchangeEntraCode, generateNonce, verifyEntraIdToken, type EntraConfig } from './entra.js';

interface NonceRecord {
  nonce: string;
  expiresAt: number;
}

const NONCE_TTL_MS = 10 * 60 * 1000;

function escapeHtml(input: string): string {
  return input.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string
  );
}

function renderPage(body: string): string {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — CIPP MCP</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1rem; box-sizing: border-box; }
  .card { background: #1e293b; padding: 2rem; border-radius: 12px; width: 100%; max-width: 360px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
  h1 { font-size: 1.1rem; margin: 0 0 .75rem; }
  p { font-size: .9rem; color: #94a3b8; }
</style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;
}

function renderError(message: string): string {
  return renderPage(`<h1>Can't sign in</h1><p>${escapeHtml(message)}</p>`);
}

/**
 * Builds the /login and /oauth/entra/callback routers as a pair sharing one
 * nonce map, since the nonce minted for a ticket at /login must be read back
 * at /callback for the same ticket.
 */
export function createEntraLoginRouterPair(
  provider: McpOAuthProvider,
  entraConfig: EntraConfig,
  allowedUpns: Set<string>,
  logger: Logger
): { loginRouter: Router; callbackRouter: Router } {
  const nonces = new Map<string, NonceRecord>();

  function sweepExpired(): void {
    const now = Date.now();
    for (const [ticket, record] of nonces) if (record.expiresAt < now) nonces.delete(ticket);
  }

  const loginRouter = express.Router();
  loginRouter.get('/login', (req, res) => {
    sweepExpired();
    const ticket = typeof req.query.ticket === 'string' ? req.query.ticket : '';
    if (!provider.getLoginTicket(ticket)) {
      res.status(400).type('html').send(renderError('This login link has expired. Go back to Claude and try connecting again.'));
      return;
    }

    const nonce = generateNonce();
    nonces.set(ticket, { nonce, expiresAt: Date.now() + NONCE_TTL_MS });
    res.redirect(302, buildEntraAuthorizeUrl(entraConfig, { state: ticket, nonce }));
  });

  const callbackRouter = express.Router();
  callbackRouter.get('/callback', async (req, res) => {
    sweepExpired();
    const ticket = typeof req.query.state === 'string' ? req.query.state : '';
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const entraError = typeof req.query.error === 'string' ? req.query.error : '';

    if (entraError) {
      logger.warn('Entra login returned an error', { error: entraError, description: req.query.error_description });
      res.status(400).type('html').send(renderError('Microsoft sign-in was cancelled or failed. Go back to Claude and try again.'));
      return;
    }

    if (!ticket || !code) {
      res.status(400).type('html').send(renderError('Invalid sign-in response. Go back to Claude and try connecting again.'));
      return;
    }

    const record = nonces.get(ticket);
    if (!record) {
      res.status(400).type('html').send(renderError('This login attempt expired. Go back to Claude and try connecting again.'));
      return;
    }
    nonces.delete(ticket);

    try {
      const idToken = await exchangeEntraCode(entraConfig, code);
      const identity = await verifyEntraIdToken(entraConfig, idToken, record.nonce);

      if (!allowedUpns.has(identity.upn.toLowerCase())) {
        logger.warn('Entra login rejected: signed-in user is not on the allowlist', { upn: identity.upn });
        res
          .status(403)
          .type('html')
          .send(renderError("Your Microsoft account isn't authorized for this server. Contact the administrator if you think this is wrong."));
        return;
      }

      const result = provider.completeLogin(ticket);
      if ('error' in result) {
        res.status(400).type('html').send(renderError(result.error));
        return;
      }

      logger.info('Entra login succeeded', { upn: identity.upn });
      res.redirect(302, result.redirectUrl);
    } catch (error) {
      logger.error('Entra login failed', error);
      res.status(500).type('html').send(renderError('Sign-in failed. Go back to Claude and try connecting again.'));
    }
  });

  return { loginRouter, callbackRouter };
}
