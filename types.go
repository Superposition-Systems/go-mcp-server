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

// ToolAnnotations holds MCP tool annotation hints (2025-03-26 spec).
// All fields are pointers so omitted hints are absent from the wire,
// not false — the spec distinguishes "unset" from "false".
type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

// ToolDef is a single MCP tool definition returned by tools/list.
//
// OutputSchema was added in the 2025-06-18 spec revision and is optional
// — tools that omit it emit the legacy wire shape. When set, clients
// that understand structured output can validate the `structuredContent`
// field returned from tools/call against it.
type ToolDef struct {
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	InputSchema  any              `json:"inputSchema"`
	OutputSchema any              `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

// BoolPtr is a convenience for building ToolAnnotations literals inline.
func BoolPtr(v bool) *bool { return &v }

// ToolResult is an optional wrapper a ToolHandler.Call implementation can
// return to emit a 2025-06-18 structuredContent block alongside (or
// instead of) the legacy text content. Returning any non-*ToolResult
// value preserves pre-v0.9 behaviour exactly: the transport marshals the
// value to JSON and emits it as a single text content block with no
// structuredContent field.
//
// The wrapper is a pointer type so the transport's type assertion
// (`result.(*ToolResult)`) distinguishes "consumer opted in" from
// "consumer returned a *ToolResult value by accident" — a value-typed
// ToolResult would collide with consumers that happen to have a struct
// of that shape.
type ToolResult struct {
	// StructuredContent is emitted as `result.structuredContent` in the
	// tools/call response. Must be JSON-marshalable; its shape should
	// match the tool's declared OutputSchema. If nil, the field is
	// omitted from the wire and only Content is sent.
	StructuredContent any

	// Content is emitted verbatim as `result.content`. If nil AND
	// StructuredContent is non-nil, the transport synthesizes a single
	// text block from StructuredContent (marshaled as JSON). This
	// fallback keeps the response renderable for clients that don't
	// understand structuredContent yet — §Tools/Backwards Compatibility
	// of the 2025-06-18 spec.
	Content []ContentBlock

	// IsError, when true, sets `result.isError` in the response. This
	// supersedes the isError bool returned alongside the *ToolResult
	// from Call, so a consumer returning *ToolResult controls error
	// state through this field alone.
	IsError bool
}

// ContentBlock is one entry in a tools/call result.content array. The
// library does not narrow the map shape because new content types (e.g.
// resource_link, audio) are added by spec revisions; consumers should
// not need a library release to emit a newly-added type.
//
// Common shapes:
//
//	{"type": "text",          "text": "..."}
//	{"type": "image",         "data": "<base64>", "mimeType": "image/png"}
//	{"type": "resource_link", "uri":  "file:///..."}
type ContentBlock = map[string]any

// TextContent is a convenience constructor for the text content block,
// by far the most common case.
func TextContent(s string) ContentBlock {
	return ContentBlock{"type": "text", "text": s}
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
