// CIPP MCP Server
// Handles the Model Context Protocol server setup and integration with CIPP.
// Supports both local (env-based) and gateway (header-based) credential modes.

import { createServer, IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { CippService } from '../services/cipp.service.js';
import { Logger, LogLevel, LogFormat } from '../utils/logger.js';
import { McpServerConfig } from '../types/index.js';
import { EnvironmentConfig, parseCredentialsFromHeaders } from '../utils/config.js';
import { CippToolHandler } from '../handlers/tool.handler.js';
import { verifyS2sHeader, S2S_HEADER } from '../s2s-verify.js';
import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { createMcpOAuthProvider } from '../oauth/mcp-oauth-provider.js';
import { createLoginRouter } from '../oauth/login-router.js';
import { createEntraLoginRouterPair } from '../oauth/entra-login-router.js';
import type { EntraConfig } from '../oauth/entra.js';

// Conduit service-to-service auth (gateway#377 parity). Non-empty =
// enforce X-Gateway-S2S on every /mcp request; empty = disabled, behavior
// exactly as before (dark-by-default until the gateway provisions this
// container's derived subkey). See src/s2s-verify.ts.
const S2S_SECRET = process.env.CONDUIT_S2S_SECRET || '';

// Static bearer-token gate for single-tenant/env-mode deployments. Non-empty =
// enforce Authorization: Bearer on every /mcp request; empty = disabled,
// dark-by-default like S2S_SECRET when unset.
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || '';

// Self-issued OAuth 2.1 gate for clients that can't send a static bearer
// header — Claude Desktop's connector UI only speaks OAuth (discovery +
// dynamic client registration + PKCE), not a header field. This does NOT
// replace MCP_AUTH_TOKEN — a request is allowed through if it satisfies
// either. See src/oauth/mcp-oauth-provider.ts for why this is a small
// self-issued AS rather than a full delegation to an external IdP, and
// needs no database.
//
// The AS is the same either way; only who's allowed to complete /login
// differs, chosen by which env vars are set:
//   - MCP_OAUTH_PASSWORD: anyone who knows the password (single-user/small
//     deployments — see src/oauth/login-router.ts).
//   - MCP_OAUTH_ENTRA_*: anyone who signs in with Microsoft AND is on
//     MCP_OAUTH_ALLOWED_UPNS (multi-user — each person authenticates as
//     themselves, with the tenant's own MFA/Conditional Access, rather than
//     sharing one password). See src/oauth/entra-login-router.ts.
// If both are configured, Entra takes priority and the password is unused.
const MCP_OAUTH_PASSWORD = process.env.MCP_OAUTH_PASSWORD || '';
const MCP_OAUTH_SIGNING_SECRET = process.env.MCP_OAUTH_SIGNING_SECRET || '';
const MCP_PUBLIC_URL =
  process.env.MCP_PUBLIC_URL ||
  (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');

const MCP_OAUTH_ENTRA_TENANT_ID = process.env.MCP_OAUTH_ENTRA_TENANT_ID || '';
const MCP_OAUTH_ENTRA_CLIENT_ID = process.env.MCP_OAUTH_ENTRA_CLIENT_ID || '';
const MCP_OAUTH_ENTRA_CLIENT_SECRET = process.env.MCP_OAUTH_ENTRA_CLIENT_SECRET || '';
const MCP_OAUTH_ALLOWED_UPNS = (process.env.MCP_OAUTH_ALLOWED_UPNS || '')
  .split(',')
  .map((upn) => upn.trim().toLowerCase())
  .filter(Boolean);

const entraVarsSet = [MCP_OAUTH_ENTRA_TENANT_ID, MCP_OAUTH_ENTRA_CLIENT_ID, MCP_OAUTH_ENTRA_CLIENT_SECRET];
if (entraVarsSet.some(Boolean) && !entraVarsSet.every(Boolean)) {
  throw new Error(
    'MCP_OAUTH_ENTRA_TENANT_ID, MCP_OAUTH_ENTRA_CLIENT_ID, and MCP_OAUTH_ENTRA_CLIENT_SECRET must be set together (all or none).'
  );
}

const ENTRA_ENABLED = entraVarsSet.every(Boolean);

if (ENTRA_ENABLED && MCP_OAUTH_ALLOWED_UPNS.length === 0) {
  throw new Error(
    'MCP_OAUTH_ENTRA_* is configured but MCP_OAUTH_ALLOWED_UPNS is empty — refusing to start with a login that would ' +
      'let anyone in the Entra tenant in. Set MCP_OAUTH_ALLOWED_UPNS to a comma-separated list of allowed UPNs/emails.'
  );
}

const OAUTH_ENABLED = ENTRA_ENABLED || Boolean(MCP_OAUTH_PASSWORD);

if (OAUTH_ENABLED && !MCP_OAUTH_SIGNING_SECRET) {
  throw new Error(
    'MCP_OAUTH_PASSWORD or MCP_OAUTH_ENTRA_* is set but MCP_OAUTH_SIGNING_SECRET is not. It signs every client ' +
      'registration and issued token for the OAuth flow and is required whenever OAuth login is enabled.'
  );
}

if (OAUTH_ENABLED && !MCP_PUBLIC_URL) {
  throw new Error(
    'OAuth login is configured but MCP_PUBLIC_URL is not. OAuth discovery needs the externally-reachable base URL ' +
      'of this server, e.g. https://cipp-mcp-production.up.railway.app.'
  );
}

const oauthProvider = OAUTH_ENABLED
  ? createMcpOAuthProvider({ password: MCP_OAUTH_PASSWORD, signingSecret: MCP_OAUTH_SIGNING_SECRET })
  : undefined;

const oauthResourceUrl = oauthProvider ? new URL('/mcp', MCP_PUBLIC_URL) : undefined;

const oauthResourceMetadataUrl = oauthResourceUrl
  ? getOAuthProtectedResourceMetadataUrl(oauthResourceUrl)
  : undefined;

const entraConfig: EntraConfig | undefined = ENTRA_ENABLED
  ? {
      tenantId: MCP_OAUTH_ENTRA_TENANT_ID,
      clientId: MCP_OAUTH_ENTRA_CLIENT_ID,
      clientSecret: MCP_OAUTH_ENTRA_CLIENT_SECRET,
      publicUrl: MCP_PUBLIC_URL,
    }
  : undefined;

// Everything the SDK's mcpAuthRouter doesn't own (metadata, /authorize,
// /token, /register, /revoke) plus the login step (password form, or a
// hand-off to Microsoft when Entra is configured), mounted as a small
// Express sub-app and dispatched to from the raw node:http handler below —
// see isOAuthAppPath(). The rest of the server (notably /mcp itself) stays
// on plain node:http; there's no reason to migrate a stateful streaming
// endpoint to Express just to gain a login form.
const oauthApp = oauthProvider
  ? (() => {
      const app = express();
      app.use(
        mcpAuthRouter({
          provider: oauthProvider,
          issuerUrl: new URL(MCP_PUBLIC_URL),
          resourceServerUrl: oauthResourceUrl,
          resourceName: 'CIPP MCP Server',
        })
      );
      if (entraConfig) {
        const entraLogger = new Logger(
          (process.env.LOG_LEVEL as LogLevel) || 'info',
          (process.env.LOG_FORMAT as LogFormat) || 'simple'
        );
        const { loginRouter, callbackRouter } = createEntraLoginRouterPair(
          oauthProvider,
          entraConfig,
          new Set(MCP_OAUTH_ALLOWED_UPNS),
          entraLogger
        );
        app.use(loginRouter);
        app.use('/oauth/entra', callbackRouter);
      } else {
        app.use('/login', createLoginRouter(oauthProvider));
      }
      return app;
    })()
  : undefined;

const OAUTH_APP_EXACT_PATHS = new Set(['/authorize', '/token', '/register', '/revoke', '/login', '/oauth/entra/callback']);
function isOAuthAppPath(pathname: string): boolean {
  return pathname.startsWith('/.well-known/') || OAUTH_APP_EXACT_PATHS.has(pathname);
}

export class CippMcpServer {
  private server: Server;
  private config: McpServerConfig;
  private cippService: CippService;
  private toolHandler: CippToolHandler;
  private logger: Logger;
  private envConfig: EnvironmentConfig | undefined;
  private httpServer?: HttpServer;

  constructor(config: McpServerConfig, logger: Logger, envConfig?: EnvironmentConfig) {
    this.logger = logger;
    this.config = config;
    this.envConfig = envConfig;

    this.cippService = new CippService(config, logger);
    this.toolHandler = new CippToolHandler(this.cippService, logger);

    this.server = this.createFreshServer();
  }

  /**
   * Create a fresh MCP Server with all handlers registered.
   * Called per-request in HTTP (stateless) mode so each initialise gets a clean server.
   */
  private createFreshServer(): Server {
    const server = new Server(
      {
        name: this.config.name,
        version: this.config.version,
      },
      {
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        instructions: this.getServerInstructions(),
      }
    );

    server.onerror = (error) => {
      this.logger.error('MCP Server error:', error);
    };

    server.oninitialized = () => {
      this.logger.info('MCP Server initialized and ready to serve requests');
    };

    this.setupHandlers(server);
    this.toolHandler.setServer(server);

    return server;
  }

  /**
   * Returns instructions that help MCP clients understand how to use this server.
   */
  private getServerInstructions(): string {
    return `
CIPP MCP Server — M365 multi-tenant management platform for MSPs.

Use tenantFilter to scope operations to a specific tenant domain (e.g. "contoso.com").
Most listing tools accept 'allTenants' as tenantFilter to query across every managed tenant.

Always confirm destructive operations (disable user, offboard user, reset password) before executing.

Tool categories:
- Tenants: list and inspect managed tenants
- Users: list, create, edit, disable, offboard, MFA/session management, BEC check
- Groups: list and create Azure AD groups
- Mailboxes: list mailboxes and permissions, configure OoO and forwarding
- Security: Conditional Access policies, named locations
- Standards: compliance standards, BPA results, domain health
- Licenses: per-tenant and CSP-level license reporting
- Alerts: audit logs and alert queue
- GDAP: roles and relationship invites
- Scheduler: list and create scheduled tasks
- Core: ping, version, logs
`.trim();
  }

  /**
   * Register all MCP request handlers on the given server instance.
   */
  private setupHandlers(server: Server): void {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      this.logger.debug('Handling list tools request');
      return { tools: this.toolHandler.getToolDefinitions() };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug(`Handling tool call: ${request.params.name}`);
      try {
        const result = await this.toolHandler.handleToolCall(
          request.params.name,
          (request.params.arguments as Record<string, unknown>) || {}
        );
        return {
          content: result.content,
          isError: result.isError,
        };
      } catch (error) {
        this.logger.error(`Failed to call tool ${request.params.name}:`, error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [{ type: 'text', text: message }],
          isError: true,
        };
      }
    });

  }

  /**
   * Start the server using the configured transport type.
   */
  async start(): Promise<void> {
    const transportType = this.envConfig?.transport?.type || 'stdio';
    this.logger.info(`Starting CIPP MCP Server with ${transportType} transport...`);

    if (transportType === 'http') {
      await this.startHttpTransport();
    } else {
      await this.startStdioTransport();
    }
  }

  private async startStdioTransport(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info('CIPP MCP Server started on stdio transport');
  }

  private async startHttpTransport(): Promise<void> {
    const port = this.envConfig?.transport?.port || 8080;
    const host = this.envConfig?.transport?.host || '0.0.0.0';

    this.httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      if (oauthApp && isOAuthAppPath(url.pathname)) {
        oauthApp(req, res);
        return;
      }

      if (url.pathname === '/mcp') {
        void this.handleMcpRequest(req, res);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
    });

    await new Promise<void>((resolve) => {
      this.httpServer!.listen(port, host, () => {
        this.logger.info(`CIPP MCP Server listening on http://${host}:${port}/mcp`);
        this.logger.info(`Health check available at http://${host}:${port}/health`);
        this.logger.info(
          `Authentication mode: ${this.envConfig?.auth?.mode === 'gateway' ? 'gateway (header-based)' : 'env (environment variables)'}`
        );
        const oauthMode = !OAUTH_ENABLED ? 'disabled' : ENTRA_ENABLED ? 'entra' : 'password';
        this.logger.info(
          `MCP endpoint auth: static token ${MCP_AUTH_TOKEN ? 'enabled' : 'disabled'}, OAuth ${oauthMode}`
        );
        resolve();
      });
    });
  }

  /**
   * Checks whether a request to /mcp carries a valid credential — either the
   * static MCP_AUTH_TOKEN bearer header, or a valid OAuth access token
   * issued by our own /token endpoint. Either is sufficient; this is an "or"
   * gate, not an "and" one, so Claude Code (header) and Claude Desktop
   * (OAuth) can both reach the same server.
   */
  private async isMcpAuthorized(req: IncomingMessage): Promise<boolean> {
    const authHeader = req.headers['authorization'];
    const provided =
      typeof authHeader === 'string' && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!provided) return false;

    if (MCP_AUTH_TOKEN) {
      const expected = Buffer.from(MCP_AUTH_TOKEN);
      const providedBuf = Buffer.from(provided);
      if (providedBuf.length === expected.length && timingSafeEqual(providedBuf, expected)) {
        return true;
      }
    }

    if (oauthProvider) {
      try {
        await oauthProvider.verifyAccessToken(provided);
        return true;
      } catch {
        // Falls through to the `return false` below.
      }
    }

    return false;
  }

  private async handleMcpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const isGatewayMode = this.envConfig?.auth?.mode === 'gateway';

    if (MCP_AUTH_TOKEN || oauthProvider) {
      if (!(await this.isMcpAuthorized(req))) {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (oauthResourceMetadataUrl) {
          headers['WWW-Authenticate'] = `Bearer resource_metadata="${oauthResourceMetadataUrl}"`;
        }
        res.writeHead(401, headers);
        res.end(JSON.stringify({ error: 'Missing or invalid Authorization bearer token.' }));
        return;
      }
    }

    // Conduit service-to-service auth (gateway#377 parity): rejected
    // BEFORE any credential extraction (OAuth or static key), mirroring
    // every other ported wrapper (e.g.
    // containers/sentinelone-mcp/gateway_wrapper.py).
    if (S2S_SECRET && !verifyS2sHeader(req.headers[S2S_HEADER] as string | undefined, S2S_SECRET)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
        })
      );
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Method not allowed' },
          id: null,
        })
      );
      return;
    }

    let toolHandler = this.toolHandler;
    let cippService = this.cippService;

    if (isGatewayMode) {
      const credentials = parseCredentialsFromHeaders(
        req.headers as Record<string, string | string[] | undefined>
      );

      const hasOAuth =
        !!credentials.tenantId && !!credentials.clientId && !!credentials.clientSecret;
      const hasStatic = !!credentials.apiKey;

      if (!credentials.baseUrl || (!hasStatic && !hasOAuth)) {
        this.logger.warn('Gateway mode: Missing required credentials in request headers', {
          hasBaseUrl: !!credentials.baseUrl,
          hasApiKey: hasStatic,
          hasOAuthCreds: hasOAuth,
        });
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Missing credentials',
            message:
              'Gateway mode requires x-base-url plus either x-api-key or (x-tenant-id + x-client-id + x-client-secret)',
            required: ['x-base-url', 'x-api-key OR (x-tenant-id + x-client-id + x-client-secret)'],
          })
        );
        return;
      }

      const requestConfig: McpServerConfig = {
        name: this.config.name,
        version: this.config.version,
        cipp: {
          baseUrl: credentials.baseUrl,
          ...(credentials.apiKey !== undefined ? { apiKey: credentials.apiKey } : {}),
          ...(credentials.tenantId !== undefined ? { tenantId: credentials.tenantId } : {}),
          ...(credentials.clientId !== undefined ? { clientId: credentials.clientId } : {}),
          ...(credentials.clientSecret !== undefined ? { clientSecret: credentials.clientSecret } : {}),
          ...(credentials.tokenScope !== undefined ? { tokenScope: credentials.tokenScope } : {}),
          ...(credentials.tokenUrl !== undefined ? { tokenUrl: credentials.tokenUrl } : {}),
        },
      };

      cippService = new CippService(requestConfig, this.logger);
      toolHandler = new CippToolHandler(cippService, this.logger);
    }

    const server = new Server(
      { name: this.config.name, version: this.config.version },
      {
        capabilities: { tools: { listChanged: true } },
        instructions: this.getServerInstructions(),
      }
    );

    server.onerror = (error) => this.logger.error('MCP request server error:', error);

    // Wire up handlers using the (possibly per-request) toolHandler
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: toolHandler.getToolDefinitions(),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug(`Handling tool call: ${request.params.name}`);
      try {
        const result = await toolHandler.handleToolCall(
          request.params.name,
          (request.params.arguments as Record<string, unknown>) || {}
        );
        return { content: result.content, isError: result.isError };
      } catch (error) {
        this.logger.error(`Failed to call tool ${request.params.name}:`, error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [{ type: 'text', text: message }],
          isError: true,
        };
      }
    });

    toolHandler.setServer(server);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      transport.close();
      server.close();
    });

    server
      .connect(transport as any)
      .then(() => {
        transport.handleRequest(req, res);
      })
      .catch((err) => {
        this.logger.error('MCP transport connect error:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal error' },
              id: null,
            })
          );
        }
      });
  }

  /**
   * Gracefully stop the server.
   */
  async stop(): Promise<void> {
    this.logger.info('Stopping CIPP MCP Server...');
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
    }
    await this.server.close();
    this.logger.info('CIPP MCP Server stopped');
  }
}
