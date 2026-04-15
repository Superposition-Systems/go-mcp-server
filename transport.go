package mcpserver

import (
	"encoding/json"
	"fmt"
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
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
		})
		return
	}
	// JSON-RPC 2.0 §4.2: id MUST be a string, number, or null. We also
	// cap string ids at 256 bytes so we do not echo arbitrarily large
	// attacker-controlled content in every response.
	if !validRPCID(req.ID) {
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
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32600, Message: "Invalid Request: params too large"},
		})
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
