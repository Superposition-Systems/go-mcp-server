package mcpserver

import (
	"encoding/json"
	"fmt"
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
func TransportHandler(info ServerInfo, tools ToolHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		handlePost(w, r, info, tools)
	}
}

func handlePost(w http.ResponseWriter, r *http.Request, info ServerInfo, tools ToolHandler) {
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      "server-error",
			Error:   &RPCError{Code: -32600, Message: "Not Acceptable: Client must accept both application/json and text/event-stream"},
		})
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      "server-error",
			Error:   &RPCError{Code: -32600, Message: "Unsupported Media Type: Content-Type must be application/json"},
		})
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
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
		handleToolsCall(w, r, req, tools)
	default:
		writeSSE(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
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

func handleToolsCall(w http.ResponseWriter, r *http.Request, req JSONRPCRequest, tools ToolHandler) {
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

	result, isError := tools.Call(r.Context(), params.Name, params.Arguments)

	content := []map[string]any{
		{"type": "text", "text": toJSON(result)},
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

	data, _ := json.Marshal(resp)
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
