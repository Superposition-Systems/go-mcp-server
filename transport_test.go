package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockToolHandler implements ToolHandler for testing.
type mockToolHandler struct {
	tools  []ToolDef
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

	// When the client sends no protocolVersion, the server echoes its
	// newest supported version (supportedProtocolVersions[0]). This
	// asserts the default-advertised version rather than pinning a
	// specific literal so version bumps only need to update the slice.
	if result["protocolVersion"] != supportedProtocolVersions[0] {
		t.Errorf("expected protocolVersion %q, got %q", supportedProtocolVersions[0], result["protocolVersion"])
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

// TestInitializeProtocolVersionNegotiation covers the three branches of
// negotiateProtocolVersion: exact support (echo verbatim), unsupported
// (fall back to newest), and backwards-compat for the old pinned
// constant. These are protocol-boundary assertions — a regression here
// is a spec-conformance regression, not a local bug.
func TestInitializeProtocolVersionNegotiation(t *testing.T) {
	handler, _ := newTestHandler()

	cases := []struct {
		name      string
		requested string
		want      string
	}{
		{"newest supported echoed verbatim", protocolVersion20250618, protocolVersion20250618},
		{"older supported echoed verbatim", protocolVersion20250326, protocolVersion20250326},
		{"unsupported falls back to newest", "2024-11-05", protocolVersion20250618},
		{"empty falls back to newest", "", protocolVersion20250618},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{}
			if tc.requested != "" {
				params["protocolVersion"] = tc.requested
			}
			rec := doPost(handler, "initialize", params)
			resp := parseSSEResponse(t, rec.Body.String())
			if resp.Error != nil {
				t.Fatalf("unexpected error: %v", resp.Error)
			}
			result := resp.Result.(map[string]any)
			if result["protocolVersion"] != tc.want {
				t.Errorf("requested %q: expected protocolVersion %q, got %q", tc.requested, tc.want, result["protocolVersion"])
			}
		})
	}
}

// TestMCPProtocolVersionHeader covers the post-initialize header
// validation: supported values pass through, unsupported values are
// rejected with JSON-RPC -32600, and absence is tolerated (legacy
// 2025-03-26 clients never send the header).
func TestMCPProtocolVersionHeader(t *testing.T) {
	handler, _ := newTestHandler()

	build := func(protocolVer string) *http.Request {
		body := JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/list"}
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(data))
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Content-Type", "application/json")
		if protocolVer != "" {
			req.Header.Set(mcpProtocolVersionHeader, protocolVer)
		}
		return req
	}

	cases := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"absent header is tolerated (legacy client)", "", false},
		{"supported 2025-06-18 header accepted", protocolVersion20250618, false},
		{"supported 2025-03-26 header accepted", protocolVersion20250326, false},
		{"unsupported header rejected", "2024-11-05", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, build(tc.header))
			resp := parseSSEResponse(t, rec.Body.String())
			if tc.wantErr {
				if resp.Error == nil {
					t.Fatalf("expected JSON-RPC error, got success")
				}
				if resp.Error.Code != -32600 {
					t.Errorf("expected code -32600, got %d", resp.Error.Code)
				}
			} else if resp.Error != nil {
				t.Errorf("unexpected error: %v", resp.Error)
			}
		})
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

// TestToolsCallStructuredContent exercises the *ToolResult opt-in path
// introduced in v0.9 for the 2025-06-18 structured-content capability.
// The four sub-tests together assert:
//
//   - structured + explicit content → both fields present, unchanged
//   - structured only → text content is synthesized from the structured
//     payload so legacy clients still render (spec §Tools/Backcompat)
//   - explicit content only → structuredContent field omitted entirely
//     (not "null"; clients MUST be able to distinguish absent from null)
//   - IsError on *ToolResult → response isError reflects it even when
//     the outer Call bool is false
//
// Regressions here are protocol-boundary; the synthesize-text behaviour
// in particular is what keeps 2025-03-26 clients working after a
// consumer adopts structured output.
func TestToolsCallStructuredContent(t *testing.T) {
	mock := &mockToolHandler{
		tools: []ToolDef{{Name: "echo", Description: "", InputSchema: map[string]any{"type": "object"}}},
	}
	info := ServerInfo{Name: "test", Version: "1.0.0"}
	handler := TransportHandler(info, mock)

	t.Run("structured plus explicit content", func(t *testing.T) {
		mock.callFn = func(context.Context, string, map[string]any) (any, bool) {
			return &ToolResult{
				StructuredContent: map[string]any{"result": 42},
				Content:           []ContentBlock{TextContent("human-readable summary")},
			}, false
		}
		rec := doPost(handler, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}})
		resp := parseSSEResponse(t, rec.Body.String())
		result := resp.Result.(map[string]any)

		sc, ok := result["structuredContent"].(map[string]any)
		if !ok || sc["result"] != float64(42) {
			t.Errorf("expected structuredContent.result=42, got %v", result["structuredContent"])
		}
		content := result["content"].([]any)
		if first := content[0].(map[string]any); first["text"] != "human-readable summary" {
			t.Errorf("expected consumer-supplied text, got %v", first["text"])
		}
	})

	t.Run("structured only synthesizes text", func(t *testing.T) {
		mock.callFn = func(context.Context, string, map[string]any) (any, bool) {
			return &ToolResult{StructuredContent: map[string]any{"x": "y"}}, false
		}
		rec := doPost(handler, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}})
		resp := parseSSEResponse(t, rec.Body.String())
		result := resp.Result.(map[string]any)

		content := result["content"].([]any)
		if len(content) != 1 {
			t.Fatalf("expected 1 synthesized content block, got %d", len(content))
		}
		first := content[0].(map[string]any)
		if first["type"] != "text" {
			t.Errorf("expected synthesized block type 'text', got %v", first["type"])
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(first["text"].(string)), &parsed); err != nil {
			t.Fatalf("synthesized text is not valid JSON: %v", err)
		}
		if parsed["x"] != "y" {
			t.Errorf("expected synthesized text to contain structured payload, got %v", parsed)
		}
	})

	t.Run("content only omits structuredContent field", func(t *testing.T) {
		mock.callFn = func(context.Context, string, map[string]any) (any, bool) {
			return &ToolResult{Content: []ContentBlock{TextContent("plain")}}, false
		}
		rec := doPost(handler, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}})
		resp := parseSSEResponse(t, rec.Body.String())
		result := resp.Result.(map[string]any)

		if _, present := result["structuredContent"]; present {
			t.Error("structuredContent must be absent (not null) when consumer provides content only")
		}
	})

	t.Run("IsError on ToolResult surfaces", func(t *testing.T) {
		mock.callFn = func(context.Context, string, map[string]any) (any, bool) {
			return &ToolResult{
				StructuredContent: map[string]any{"err": "bad input"},
				IsError:           true,
			}, false // outer bool is false — ToolResult.IsError must win
		}
		rec := doPost(handler, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}})
		resp := parseSSEResponse(t, rec.Body.String())
		result := resp.Result.(map[string]any)

		if result["isError"] != true {
			t.Errorf("expected isError=true from ToolResult.IsError, got %v", result["isError"])
		}
	})
}

// TestToolsListOutputSchemaAbsentWhenUnset pins the wire-level omission of
// OutputSchema for tools that don't declare one. This is the
// backwards-compat guarantee: an existing consumer that compiles against
// v0.9 without changing its tool definitions produces the exact same
// tools/list bytes as before. The typed-nil pitfall in registry.go —
// where a nil json.RawMessage wrapped in `any` would marshal to `null`
// instead of being absent — is what this test is actually defending.
func TestToolsListOutputSchemaAbsentWhenUnset(t *testing.T) {
	handler, _ := newTestHandler()
	rec := doPost(handler, "tools/list", nil)
	resp := parseSSEResponse(t, rec.Body.String())
	result := resp.Result.(map[string]any)
	tools := result["tools"].([]any)
	for _, raw := range tools {
		tool := raw.(map[string]any)
		if _, present := tool["outputSchema"]; present {
			t.Errorf("tool %q: outputSchema should be absent when unset, got %v", tool["name"], tool["outputSchema"])
		}
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

// TestNotificationByAbsentID exercises JSON-RPC 2.0 §4.1: a request with
// no "id" field is a notification for ANY method name, and the server
// MUST NOT reply. Prior to the transport fix, an absent id decoded to the
// same `nil` as an explicit null id, and arbitrary notifications fell
// through to the default -32601 path — observable as a spec violation
// from any strict client.
func TestNotificationByAbsentID(t *testing.T) {
	handler, _ := newTestHandler()

	// Explicitly omit id — this is the important case.
	for _, method := range []string{"ping", "tools/list", "custom/notification", "bogus"} {
		body := `{"jsonrpc":"2.0","method":"` + method + `"}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Errorf("method %q without id: expected 202, got %d (body=%q)", method, rec.Code, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Errorf("method %q without id: expected empty body, got %q", method, rec.Body.String())
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

	if rec.Code != http.StatusNotAcceptable {
		t.Errorf("expected 406, got %d", rec.Code)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
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

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rec.Code)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
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
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Errorf("expected Allow: POST header, got %q", allow)
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

// ─────────────────────────────────────────────────────────────────────────────
// v0.8.0 track 1B — middleware chain wired into tools/call
// ─────────────────────────────────────────────────────────────────────────────

// newChainHandler builds a TransportHandlerWithMiddleware over a Registry so
// the tests exercise the actual production wiring (not a hand-rolled chain).
func newChainHandler(t *testing.T, reg *Registry, mws ...ToolMiddleware) http.HandlerFunc {
	t.Helper()
	info := ServerInfo{Name: "mw-test", Version: "1.0.0"}
	tools := reg.AsToolHandler()
	chain := applyMiddlewares(adaptToolHandler(tools), mws)
	return TransportHandlerWithMiddleware(info, tools, chain)
}

// TestToolsCall_MiddlewareRunsAndMutatesResult proves a user-installed
// ToolMiddleware can append to the result visible on the wire.
func TestToolsCall_MiddlewareRunsAndMutatesResult(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(Tool{
		Name:        "echo",
		Description: "echo",
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			return map[string]any{"input": args["msg"]}, nil
		},
	})

	marker := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			r, ie, err := next(ctx, n, args)
			if err == nil && !ie {
				m, ok := r.(map[string]any)
				if ok {
					m["__mw_marker"] = true
					r = m
				}
			}
			return r, ie, err
		}
	}

	handler := newChainHandler(t, reg, marker)
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"msg": "hi"},
	})

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] != false {
		t.Errorf("expected isError=false, got %v", result["isError"])
	}
	content := result["content"].([]any)
	first := content[0].(map[string]any)
	if !strings.Contains(first["text"].(string), `"__mw_marker":true`) {
		t.Fatalf("middleware marker missing from payload: %s", first["text"])
	}
	if !strings.Contains(first["text"].(string), `"input":"hi"`) {
		t.Fatalf("original handler output missing: %s", first["text"])
	}
}

// TestToolsCall_MiddlewareLibraryError proves a middleware returning
// err != nil surfaces as isError=true with the error text in content
// (§3.3 library-error shape).
func TestToolsCall_MiddlewareLibraryError(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(Tool{
		Name: "x",
		Handler: func(context.Context, map[string]any) (any, error) {
			t.Fatal("handler must not run when middleware returns err")
			return nil, nil
		},
	})
	boom := errors.New("middleware boom")
	shortCircuit := func(ToolCallFunc) ToolCallFunc {
		return func(context.Context, string, map[string]any) (any, bool, error) {
			return nil, false, boom
		}
	}

	handler := newChainHandler(t, reg, shortCircuit)
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "x",
		"arguments": map[string]any{},
	})

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("library errors must surface via MCP isError, not JSON-RPC error; got %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Fatalf("expected isError=true for library err, got %v", result["isError"])
	}
	content := result["content"].([]any)
	first := content[0].(map[string]any)
	if !strings.Contains(first["text"].(string), "middleware boom") {
		t.Fatalf("expected error text in content, got %q", first["text"])
	}
}

// TestToolsCall_MiddlewareToolLevelError proves that isError=true with
// err==nil is distinct from the library-error case — the handler runs
// and its own payload is what ends up on the wire. Verifies §3.3.
func TestToolsCall_MiddlewareToolLevelError(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(Tool{
		Name: "t",
		Handler: func(context.Context, map[string]any) (any, error) {
			// Simulates the adapter path: a tool reporting a tool-level
			// failure with a structured payload.
			return nil, errors.New("REMOTE 404: issue not found")
		},
	})
	// Pure observer middleware — does NOT return err, just records.
	observed := false
	observer := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			r, ie, err := next(ctx, n, args)
			// Observer sees isError=true, err=nil — tool-level error.
			if ie && err == nil {
				observed = true
			}
			return r, ie, err
		}
	}

	handler := newChainHandler(t, reg, observer)
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "t",
		"arguments": map[string]any{},
	})

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Errorf("expected isError=true, got %v", result["isError"])
	}
	content := result["content"].([]any)
	first := content[0].(map[string]any)
	// The handler's error path flows through registryHandler.Call as a
	// tool-level isError with a structured content envelope — assert the
	// error text reaches the wire.
	if !strings.Contains(first["text"].(string), "REMOTE 404") {
		t.Fatalf("expected tool-level error text on wire, got %q", first["text"])
	}
	if !observed {
		t.Fatal("observer middleware did not see isError=true, err==nil — chain ordering wrong")
	}
}

// TestToolsCall_BypassMethods_DoNotInvokeMiddleware wires a middleware
// whose presence would be observable (a counter) and fires all the
// non-tools/call methods through the transport. Per §5, the chain
// only runs for tools/call.
func TestToolsCall_BypassMethods_DoNotInvokeMiddleware(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(Tool{
		Name: "echo",
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			return args, nil
		},
	})

	var invocations int
	// A panic-on-invoke counter is overkill because a panic becomes a
	// test failure through the default recover; instead, we atomic-sum
	// an int and assert it stays at zero after the bypass fires.
	counter := func(next ToolCallFunc) ToolCallFunc {
		return func(ctx context.Context, n string, args map[string]any) (any, bool, error) {
			invocations++
			return next(ctx, n, args)
		}
	}

	handler := newChainHandler(t, reg, counter)

	// initialize, tools/list, ping, and notifications/* all bypass the
	// chain. Fire each and assert the counter stays at zero.
	for _, method := range []string{"initialize", "tools/list", "ping", "notifications/initialized", "notifications/cancelled"} {
		rec := doPost(handler, method, nil)
		// notifications return 202, everything else returns 200 via SSE.
		// We don't need to assert the body here — the existing tests
		// already do that. We just need a round trip.
		_ = rec
	}
	if invocations != 0 {
		t.Fatalf("bypass methods invoked the middleware chain %d times; expected 0 (§5)", invocations)
	}

	// Sanity check: tools/call DOES invoke the chain.
	rec := doPost(handler, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"a": 1},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/call failed: %d", rec.Code)
	}
	if invocations != 1 {
		t.Fatalf("expected middleware to run exactly once for tools/call, got %d", invocations)
	}
}

func TestToolsCallMarshalError(t *testing.T) {
	info := ServerInfo{Name: "test", Version: "1.0.0"}
	mock := &mockToolHandler{
		tools: []ToolDef{{Name: "bad", Description: "Returns unmarshalable", InputSchema: map[string]any{"type": "object"}}},
		callFn: func(ctx context.Context, name string, args map[string]any) (any, bool) {
			return func() {}, false // functions can't be marshalled
		},
	}
	handler := TransportHandler(info, mock)
	rec := doPost(handler, "tools/call", map[string]any{"name": "bad", "arguments": map[string]any{}})

	resp := parseSSEResponse(t, rec.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Error("expected isError to be true when marshal fails")
	}
	content := result["content"].([]any)
	first := content[0].(map[string]any)
	if !strings.Contains(first["text"].(string), "failed to marshal") {
		t.Errorf("expected marshal error in content text, got: %s", first["text"])
	}
}
