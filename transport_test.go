package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockToolHandler implements ToolHandler for testing.
type mockToolHandler struct {
	tools []ToolDef
	callFn func(ctx context.Context, name string, args map[string]any) (any, bool)
}

func (m *mockToolHandler) ListTools() []ToolDef {
	return m.tools
}

func (m *mockToolHandler) Call(ctx context.Context, name string, args map[string]any) (any, bool) {
	if m.callFn != nil {
		return m.callFn(ctx, name, args)
	}
	return map[string]string{"error": "unknown tool"}, true
}

func newTestHandler() (http.HandlerFunc, *mockToolHandler) {
	mock := &mockToolHandler{
		tools: []ToolDef{
			{Name: "echo", Description: "Echoes input", InputSchema: map[string]any{"type": "object"}},
			{Name: "greet", Description: "Greets user", InputSchema: map[string]any{"type": "object"}},
		},
		callFn: func(ctx context.Context, name string, args map[string]any) (any, bool) {
			if name == "echo" {
				return args, false
			}
			return map[string]string{"error": "not found"}, true
		},
	}
	info := ServerInfo{Name: "test-server", Version: "1.0.0", Instructions: "A test server"}
	return TransportHandler(info, mock), mock
}

func doPost(handler http.HandlerFunc, method string, params any) *httptest.ResponseRecorder {
	body := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
	}
	if params != nil {
		raw, _ := json.Marshal(params)
		body.Params = raw
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func parseSSEResponse(t *testing.T, body string) JSONRPCResponse {
	t.Helper()
	// SSE format: "event: message\ndata: {json}\n\n"
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			var resp JSONRPCResponse
			if err := json.Unmarshal([]byte(line[6:]), &resp); err != nil {
				t.Fatalf("failed to parse SSE data: %v", err)
			}
			return resp
		}
	}
	t.Fatalf("no SSE data line found in response body: %q", body)
	return JSONRPCResponse{}
}

func TestInitialize(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "initialize", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}

	if result["protocolVersion"] != protocolVersion {
		t.Errorf("expected protocolVersion %q, got %q", protocolVersion, result["protocolVersion"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("serverInfo missing")
	}
	if serverInfo["name"] != "test-server" {
		t.Errorf("expected name test-server, got %v", serverInfo["name"])
	}
	if serverInfo["version"] != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %v", serverInfo["version"])
	}
	if result["instructions"] != "A test server" {
		t.Errorf("expected instructions, got %v", result["instructions"])
	}
}

func TestToolsList(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "tools/list", nil)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result := resp.Result.(map[string]any)
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatal("tools is not an array")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	first := tools[0].(map[string]any)
	if first["name"] != "echo" {
		t.Errorf("expected first tool name 'echo', got %v", first["name"])
	}
}

func TestToolsCall(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "hello"},
	})

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result := resp.Result.(map[string]any)
	if result["isError"] != false {
		t.Error("expected isError to be false")
	}

	content := result["content"].([]any)
	if len(content) == 0 {
		t.Fatal("expected content")
	}
	first := content[0].(map[string]any)
	if first["type"] != "text" {
		t.Errorf("expected type 'text', got %v", first["type"])
	}
	// The text field contains JSON-encoded result
	var parsed map[string]any
	if err := json.Unmarshal([]byte(first["text"].(string)), &parsed); err != nil {
		t.Fatalf("text is not valid JSON: %v", err)
	}
	if parsed["message"] != "hello" {
		t.Errorf("expected message 'hello', got %v", parsed["message"])
	}
}

func TestToolsCallError(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "nonexistent",
		"arguments": map[string]any{},
	})

	resp := parseSSEResponse(t, rec.Body.String())
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Error("expected isError to be true for unknown tool")
	}
}

func TestPing(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "ping", nil)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result := resp.Result.(map[string]any)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestNotificationsReturn202(t *testing.T) {
	handler, _ := newTestHandler()

	for _, method := range []string{"notifications/initialized", "notifications/cancelled"} {
		rec := doPost(handler, method, nil)
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s: expected 202, got %d", method, rec.Code)
		}
	}
}

func TestUnknownMethodReturns32601(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "bogus/method", nil)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "bogus/method") {
		t.Errorf("expected method name in error message, got %q", resp.Error.Message)
	}
}

func TestInvalidAcceptHeader(t *testing.T) {
	handler, _ := newTestHandler()

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Accept", "application/json") // missing text/event-stream
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error == nil {
		t.Fatal("expected error for invalid Accept header")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected error code -32600, got %d", resp.Error.Code)
	}
}

func TestInvalidContentType(t *testing.T) {
	handler, _ := newTestHandler()

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler(rec, req)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error == nil {
		t.Fatal("expected error for invalid Content-Type")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected error code -32600, got %d", resp.Error.Code)
	}
}

func TestMalformedJSONBody(t *testing.T) {
	handler, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{invalid json"))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("expected error code -32700, got %d", resp.Error.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestSSEContentType(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "ping", nil)

	ct := rec.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}
}

func TestToolsCallInvalidParams(t *testing.T) {
	handler, _ := newTestHandler()

	// Send tools/call with params that can't be unmarshalled to the expected struct
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602, got %d", resp.Error.Code)
	}
}
