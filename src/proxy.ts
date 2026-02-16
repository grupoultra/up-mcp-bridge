#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { connectToRemoteServer, log, debugLog, mcpProxy, parseCommandLineArgs, setupSignalHandlers, TransportStrategy, ReconnectOptions, MCP_REMOTE_VERSION } from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { createLazyAuthCoordinator } from './lib/coordination'
import { fetchAuthorizationServerMetadata } from './lib/authorization-server-metadata'

// Handle --version and --help before parsing other arguments
const args = process.argv.slice(2)
if (args.includes('--version') || args.includes('-v')) {
  console.log(`up-mcp-bridge v${MCP_REMOTE_VERSION}`)
  process.exit(0)
}
if (args.includes('--help') || args.includes('-h')) {
  console.log(`up-mcp-bridge v${MCP_REMOTE_VERSION}

Usage: npx up-mcp-bridge <server-url> [options]

Options:
  --version, -v                Show version number
  --help, -h                   Show this help message
  --debug                      Enable debug logging
  --auto-reconnect             Enable automatic reconnection (never gives up)
  --max-reconnect-attempts N   Fast phase attempts with backoff (default: 20)
  --reconnect-delay N          Base delay between fast attempts in ms (default: 1000)
  --max-reconnect-delay N      Maximum delay in fast phase in ms (default: 15000)
  --persistent-retry-delay N   Fixed delay in persistent phase in ms (default: 30000)
  --connection-timeout N       Connection timeout in ms (default: 5000)
  --transport STRATEGY         Transport strategy: sse-only, http-only, sse-first, http-first
  --header "Key: Value"        Add custom header (can be repeated)
  --timeout N                  Request timeout in ms (default: 60000)

Reconnection behavior (two-phase):
  Fast phase:       Attempts 1-N with exponential backoff (1s→2s→4s→...→15s)
  Persistent phase: After N attempts, retries every 30s indefinitely until
                    the gateway recovers or the client disconnects.

Example:
  npx up-mcp-bridge http://localhost:3000/sse --auto-reconnect
`)
  process.exit(0)
}

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  host: string,
  staticOAuthClientMetadata: StaticOAuthClientMetadata,
  staticOAuthClientInfo: StaticOAuthClientInformationFull,
  authorizeResource: string,
  ignoredTools: string[],
  authTimeoutMs: number,
  serverUrlHash: string,
  reconnectOptions: ReconnectOptions,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Create a lazy auth coordinator
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs)

  // Pre-fetch authorization server metadata for scope validation
  let authorizationServerMetadata
  try {
    authorizationServerMetadata = await fetchAuthorizationServerMetadata(serverUrl)
    if (authorizationServerMetadata?.scopes_supported) {
      debugLog('Pre-fetched authorization server metadata', {
        scopes_supported: authorizationServerMetadata.scopes_supported,
      })
    }
  } catch (error) {
    debugLog('Failed to pre-fetch authorization server metadata', error)
  }

  // Create the OAuth client provider
  const authProvider = new NodeOAuthClientProvider({
    serverUrl,
    callbackPort,
    host,
    clientName: 'MCP CLI Proxy',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    serverUrlHash,
    authorizationServerMetadata,
  })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Keep track of the server instance for cleanup
  let server: any = null

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, just log that we'll use the auth from disk
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk')
      // TODO: remove, the callback is happening before the tokens are exchanged
      //  so we're slightly too early
      await new Promise((res) => setTimeout(res, 1_000))
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication
    const remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)

    // Create a reconnect function that will establish a new connection to the remote server
    const reconnectFn = async () => {
      log('Creating new connection to remote server...')
      return connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)
    }

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      reconnectFn,
      reconnectOptions,
      serverUrl,
    })

    // Start the local STDIO server
    await localTransport.start()
    log('Local STDIO server running')
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
    if (reconnectOptions.enabled) {
      log(`Auto-reconnect enabled (fast: ${reconnectOptions.maxAttempts} attempts, persistent: every ${(reconnectOptions.persistentRetryDelayMs ?? 30000) / 1000}s, never gives up)`)
    }
    log('Press Ctrl+C to exit')

    // Setup cleanup handler
    // IMPORTANT: Close local transport FIRST to set transportToClientClosed=true
    // This prevents the remote transport's onclose handler from attempting reconnection
    const cleanup = async () => {
      await localTransport.close()   // Must be first to prevent reconnection attempt
      await remoteTransport.close()
      // Only close the server if it was initialized
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx proxy.ts <https://server-url> [callback-port] [--debug]')
  .then(
    ({
      serverUrl,
      callbackPort,
      headers,
      transportStrategy,
      host,
      debug,
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authorizeResource,
      ignoredTools,
      authTimeoutMs,
      serverUrlHash,
      reconnectOptions,
    }) => {
      return runProxy(
        serverUrl,
        callbackPort,
        headers,
        transportStrategy,
        host,
        staticOAuthClientMetadata,
        staticOAuthClientInfo,
        authorizeResource,
        ignoredTools,
        authTimeoutMs,
        serverUrlHash,
        reconnectOptions,
      )
    },
  )
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
