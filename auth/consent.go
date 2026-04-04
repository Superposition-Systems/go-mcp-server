package auth

import "html"

// RenderPINPage generates the HTML consent page for OAuth PIN authorization.
// The title and description are parameterised so each MCP server can brand
// its own consent flow.
func RenderPINPage(title, description, authContext, errorMsg string) string {
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = `<p style="color:#de350b;margin:0 0 16px">` + html.EscapeString(errorMsg) + `</p>`
	}
	return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(title) + ` — Authorization</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f4f5f7;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:40px;max-width:400px;width:100%}
h1{font-size:24px;margin:0 0 8px;color:#172b4d}
p.desc{color:#6b778c;margin:0 0 24px;font-size:14px}
label{display:block;font-size:14px;font-weight:600;color:#172b4d;margin-bottom:8px}
input[type=password]{width:100%;padding:10px 12px;border:2px solid #dfe1e6;border-radius:4px;font-size:16px;box-sizing:border-box;letter-spacing:4px;text-align:center}
input[type=password]:focus{border-color:#0052cc;outline:none}
button{width:100%;padding:10px;background:#0052cc;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:600;cursor:pointer;margin-top:16px}
button:hover{background:#0747a6}
</style>
</head><body>
<div class="card">
<h1>` + html.EscapeString(title) + `</h1>
<p class="desc">` + html.EscapeString(description) + `</p>
` + errorHTML + `
<form method="POST" action="/authorize">
<input type="hidden" name="auth_context" value="` + html.EscapeString(authContext) + `">
<label for="pin">Authorization PIN</label>
<input type="password" id="pin" name="pin" required autofocus maxlength="20" autocomplete="off">
<button type="submit">Authorize</button>
</form>
</div>
</body></html>`
}
