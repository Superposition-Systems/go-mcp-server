package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const protocolVersion = "2025-03-26"

// TransportHandler returns an http.HandlerFunc for the MCP endpoint.
// It handles JSON-RPC 2.0 requests over HTTP with SSE responses.
//
// This handler is router-agnostic — mount it on any router or stdlib ServeMux:
//
//	mux.HandleFunc("POST /mcp", mcpserver.TransportHandler(info, tools))
//
// This constructor installs no middleware; tools/call dispatches directly
// to tools.Call. Consumers wanting middleware (v0.8.0+) should use
// TransportHandlerWithMiddleware.
func TransportHandler(info ServerInfo, tools ToolHandler) http.HandlerFunc {
	return TransportHandlerWithMiddleware(info, tools, nil)
}

// TransportHandlerWithMiddleware is the chain-aware variant of
// TransportHandler. The supplied ToolCallFunc is invoked for every
// tools/call request; initialize, tools/list, ping, and notifications
// bypass it per §5 of the v0.8.0 plan. If chain is nil, tools/call
// falls back to adapting tools.Call directly — identical behaviour to
// TransportHandler.
func TransportHandlerWithMiddleware(info ServerInfo, tools ToolHandler, chain ToolCallFunc) http.HandlerFunc {
	if chain == nil {
		chain = adaptToolHandler(tools)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		handlePost(w, r, info, tools, chain)
	}
}

func handlePost(w http.ResponseWriter, r *http.Request, info ServerInfo, tools ToolHandler, toolCall ToolCallFunc) {
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotAcceptable)
		if err := json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      "server-error",
			Error:   &RPCError{Code: -32600, Message: "Not Acceptable: Client must accept both application/json and text/event-stream"},
		}); err != nil {
			log.Printf("mcpserver: failed to write error response: %v", err)
		}
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if err := json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      "server-error",
			Error:   &RPCError{Code: -32600, Message: "Unsupported Media Type: Content-Type must be application/json"},
		}); err != nil {
			log.Printf("mcpserver: failed to write error response: %v", err)
		}
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB
	// Buffer the body so we can decode twice: once into a raw-id envelope
	// for notification detection (§JSON-RPC 2.0 §4.1: absent id means
	// notification, server MUST NOT reply), then into JSONRPCRequest for
	// the existing dispatch flow. A single-pass decode can't distinguish
	// absent id from explicit null id once it lands in an `any` field —
	// both become Go nil.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
		})
		return
	}
	var envelope struct {
		ID json.RawMessage `json:"id,omitempty"`
	}
	// envelopeOK distinguishes "parsed, id absent" (true notification)
	// from "body is malformed JSON" (treat as a best-effort request so
	// the caller still gets a -32700 Parse error SSE response).
	envelopeOK := json.Unmarshal(bodyBytes, &envelope) == nil
	isNotification := envelopeOK && len(envelope.ID) == 0

	var req JSONRPCRequest
	if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&req); err != nil {
		if isNotification {
			// Malformed notification: per JSON-RPC §4.1 the server still
			// sends no response. This branch is effectively unreachable
			// because envelopeOK implies the body is valid JSON, which
			// the full decode would also accept — but covered for safety.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
		})
		return
	}
	// JSON-RPC 2.0 §4.2: id MUST be a string, number, or null. Skip for
	// notifications (id absent) — the spec permits any shape there
	// because the server produces no reply.
	if !isNotification && !validRPCID(req.ID) {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &RPCError{Code: -32600, Message: "Invalid Request: id must be a string, number, or null"},
		})
		return
	}
	// Cap Params to 1 MB of raw JSON — tool arguments should never need
	// more than that, and the decoded object graph can be substantially
	// larger than the encoded byte count.
	if len(req.Params) > 1<<20 {
		if isNotification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32600, Message: "Invalid Request: params too large"},
		})
		return
	}

	// A request with no id is a notification for ANY method — the server
	// MUST NOT reply (JSON-RPC §4.1). Return 202 and drop on the floor.
	//
	// The `notifications/initialized` / `notifications/cancelled` cases
	// are ALSO treated as 202 even when a client mistakenly includes an
	// id, because MCP clients in the wild occasionally do this and the
	// library has historically been lenient there. That lenient handling
	// is preserved as a compat pragma; true spec compliance only kicks in
	// for non-notification-named methods via isNotification above.
	if isNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		handleInitialize(w, req, info)
	case "notifications/initialized", "notifications/cancelled":
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		writeSSE(w, JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
	case "tools/list":
		handleToolsList(w, req, tools)
	case "tools/call":
		handleToolsCall(w, r, req, toolCall)
	default:
		method := req.Method
		if len(method) > 64 {
			method = method[:64]
		}
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", method)},
		})
	}
}

func handleInitialize(w http.ResponseWriter, req JSONRPCRequest, info ServerInfo) {
	writeSSE(w, JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    info.Name,
				"version": info.Version,
			},
			"instructions": info.Instructions,
		},
	})
}

func handleToolsList(w http.ResponseWriter, req JSONRPCRequest, tools ToolHandler) {
	writeSSE(w, JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"tools": tools.ListTools(),
		},
	})
}

// handleToolsCall dispatches tools/call through the supplied ToolCallFunc
// (the middleware chain, per §5 of the v0.8.0 plan). The three-state
// return (result, isError, err) collapses to the existing SSE/content
// shape as follows:
//
//   - err != nil: library/middleware-level failure. Serialize the error
//     text into the content array with isError=true (§3.3).
//   - isError == true, err == nil: tool-level error. Serialize result
//     as the tool's own error payload with isError=true.
//   - both false/nil: success. Serialize result with isError=false.
//
// Marshal failures are folded into the err path so the wire shape is
// always valid JSON.
func handleToolsCall(w http.ResponseWriter, r *http.Request, req JSONRPCRequest, toolCall ToolCallFunc) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32602, Message: "Invalid params"},
		})
		return
	}

	result, isError, callErr := toolCall(r.Context(), params.Name, params.Arguments)

	// Library-level error (middleware short-circuit). Put the error text
	// directly in the content array and force isError=true — this keeps
	// the wire format identical to the tool-level error case, so clients
	// don't have to distinguish. The ToolCallFunc contract (§3.3) says
	// the caller should treat err as protocol-external; we fold it into
	// the MCP isError envelope rather than a JSON-RPC error so the
	// downstream client sees a tool failure, not a transport failure.
	var text string
	if callErr != nil {
		isError = true
		text = callErr.Error()
	} else {
		marshaled, marshalErr := marshalResult(result)
		if marshalErr != nil {
			// Log server-side: on the wire this is indistinguishable from a
			// tool-level error (both isError=true), so without this line an
			// operator cannot tell a marshal bug from a genuine failing tool
			// — callErr != nil is a tool-level error, marshalErr != nil is a
			// library-level serialisation bug that deserves an alert.
			log.Printf("mcpserver: marshal tool %q result: %v", params.Name, marshalErr)
			isError = true
		}
		text = marshaled
	}

	content := []map[string]any{
		{"type": "text", "text": text},
	}

	writeSSE(w, JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": content,
			"isError": isError,
		},
	})
}

// writeSSE writes a single SSE event with the JSON-RPC response.
func writeSSE(w http.ResponseWriter, resp JSONRPCResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	data, err := json.Marshal(resp)
	if err != nil {
		// Fallback: send a hardcoded error that cannot itself fail to marshal
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error: failed to marshal response\"}}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// validRPCID enforces JSON-RPC 2.0's rule that id is string, number, or
// null. Strings are capped at 256 bytes so pathological ids cannot be
// echoed back in every response. Numbers are allowed as-is (decoded as
// float64 or json.Number depending on the decoder configuration).
func validRPCID(id any) bool {
	switch v := id.(type) {
	case nil:
		return true
	case string:
		return len(v) <= 256
	case float64, json.Number, int, int64:
		return true
	default:
		return false
	}
}

// marshalResult serializes a tool result to JSON. Returns the JSON string
// and a non-nil error if marshaling failed (caller should set isError=true).
func marshalResult(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		// Use json.Marshal for the fallback to guarantee valid JSON escaping
		fallback, _ := json.Marshal(map[string]string{"error": "failed to marshal result: " + err.Error()})
		return string(fallback), err
	}
	return string(b), nil
}
