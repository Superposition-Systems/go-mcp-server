// Package mcpserver provides a reusable Go library for building MCP
// (Model Context Protocol) servers with JSON-RPC 2.0 over SSE transport,
// OAuth 2.0 + PIN consent authentication, and deployment templates.
package mcpserver

import (
	"context"
	"encoding/json"
)

// ToolHandler is the interface that applications implement to provide
// MCP tools. The library handles all transport, auth, and protocol
// concerns — the application only needs to list its tools and handle calls.
type ToolHandler interface {
	// ListTools returns the MCP tool definitions for tools/list.
	ListTools() []ToolDef

	// Call dispatches a tool call by name with the given arguments.
	// Returns the result and whether the result represents an error.
	// When isError is true, the result is sent as an MCP error content
	// response (not an HTTP error — the protocol-level distinction matters).
	Call(ctx context.Context, name string, args map[string]any) (result any, isError bool)
}

// ToolDef is a single MCP tool definition returned by tools/list.
type ToolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// ServerInfo identifies this MCP server to clients during initialization.
type ServerInfo struct {
	Name         string // Server name (e.g. "my-mcp-server")
	Version      string // Semver version (e.g. "1.0.0")
	Instructions string // Human-readable description of what this server does
}

// JSON-RPC 2.0 types used by the transport layer.

// JSONRPCRequest represents an incoming JSON-RPC 2.0 request.
//
// ID note: an `any`-typed ID cannot distinguish an absent id (notification,
// per §4.1 — server MUST NOT reply) from an explicit `"id":null` (request
// that wants a response with a null id). Both decode to Go nil. The
// transport compensates via a two-pass decode on the raw bytes before
// dispatch; downstream handlers that need the same distinction must do
// the same (or read the spec and treat null-id requests as valid
// requests, not notifications — which is what the transport does).
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
