/**
 * Interactive password prompt for the self-issued OAuth flow. Kept as a
 * plain app-defined route (outside the MCP SDK's mcpAuthRouter, which only
 * knows the standard AS endpoints) because OAuthServerProvider#authorize
 * gets no request body to read a submitted password from — only a
 * pre-validated params object and the raw response to redirect with. So
 * authorize() redirects here with a one-time ticket, and this router does
 * the actual "does this human know the password" check before minting an
 * authorization code and bouncing back to the client's redirect_uri.
 */
import express, { Router } from 'express';
import type { McpOAuthProvider } from './mcp-oauth-provider.js';

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
  .card { background: #1e293b; padding: 2rem; border-radius: 12px; width: 100%; max-width: 320px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
  h1 { font-size: 1.1rem; margin: 0 0 1.25rem; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: .6rem .75rem; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 1rem; }
  button { width: 100%; margin-top: 1rem; padding: .6rem .75rem; border-radius: 8px; border: none; background: #6366f1; color: white; font-size: 1rem; cursor: pointer; }
  button:hover { background: #4f46e5; }
  .error { color: #f87171; font-size: .85rem; margin-top: .75rem; }
  p { font-size: .9rem; color: #94a3b8; }
</style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;
}

function renderLoginForm(ticketId: string, error?: string): string {
  return renderPage(`
    <form method="POST" action="/login">
      <h1>Sign in to CIPP MCP</h1>
      <input type="hidden" name="ticket" value="${escapeHtml(ticketId)}">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Continue</button>
      ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    </form>
  `);
}

function renderExpired(message: string): string {
  return renderPage(`<h1>Can't sign in</h1><p>${escapeHtml(message)}</p>`);
}

export function createLoginRouter(provider: McpOAuthProvider): Router {
  const router = express.Router();
  router.use(express.urlencoded({ extended: false }));

  router.get('/', (req, res) => {
    const ticket = typeof req.query.ticket === 'string' ? req.query.ticket : '';
    const pending = provider.getLoginTicket(ticket);
    if (!pending) {
      res.status(400).type('html').send(renderExpired('This login link has expired. Go back to Claude and try connecting again.'));
      return;
    }
    res.status(200).type('html').send(renderLoginForm(ticket));
  });

  router.post('/', (req, res) => {
    const ticket = typeof req.body?.ticket === 'string' ? req.body.ticket : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const result = provider.submitLogin(ticket, password);

    if ('redirectUrl' in result) {
      res.redirect(302, result.redirectUrl);
      return;
    }

    if (provider.getLoginTicket(ticket)) {
      res.status(401).type('html').send(renderLoginForm(ticket, result.error));
    } else {
      res.status(400).type('html').send(renderExpired(result.error));
    }
  });

  return router;
}
