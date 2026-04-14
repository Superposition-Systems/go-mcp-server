package auth

import "html"

// PINPageData carries the display fields for the OAuth PIN consent page.
//
// ClientName and RedirectHost are shown to the operator so they can
// visually confirm *which* OAuth client they are authorizing before
// entering the PIN. Without these, a malicious DCR-registered client
// with an attacker-controlled redirect_uri is indistinguishable from
// a legitimate one (H-1 in the 2026-04-14 audit).
type PINPageData struct {
	Title        string
	Description  string
	AuthContext  string
	ErrorMsg     string
	ClientName   string // registered client_name, empty on pre-client-lookup errors
	RedirectHost string // host portion of the redirect_uri, empty on pre-client-lookup errors
}

// RenderPINPage generates the HTML consent page for OAuth PIN authorization.
// Every dynamic field is html.EscapeString'd before interpolation.
func RenderPINPage(d PINPageData) string {
	errorHTML := ""
	if d.ErrorMsg != "" {
		errorHTML = `<p style="color:#de350b;margin:0 0 16px">` + html.EscapeString(d.ErrorMsg) + `</p>`
	}
	clientHTML := ""
	if d.ClientName != "" || d.RedirectHost != "" {
		name := d.ClientName
		if name == "" {
			name = "(unnamed client)"
		}
		host := d.RedirectHost
		if host == "" {
			host = "(unknown redirect)"
		}
		clientHTML = `<div style="background:#f4f5f7;border-radius:4px;padding:12px 14px;margin:0 0 20px;font-size:13px;color:#172b4d;line-height:1.5">` +
			`<div style="color:#6b778c;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Authorizing client</div>` +
			`<div style="font-weight:600">` + html.EscapeString(name) + `</div>` +
			`<div style="color:#6b778c;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all">` + html.EscapeString(host) + `</div>` +
			`</div>`
	}
	return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(d.Title) + ` — Authorization</title>
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
<h1>` + html.EscapeString(d.Title) + `</h1>
<p class="desc">` + html.EscapeString(d.Description) + `</p>
` + clientHTML + errorHTML + `
<form method="POST" action="/authorize">
<input type="hidden" name="auth_context" value="` + html.EscapeString(d.AuthContext) + `">
<label for="pin">Authorization PIN</label>
<input type="password" id="pin" name="pin" required autofocus maxlength="20" autocomplete="off">
<button type="submit">Authorize</button>
</form>
</div>
</body></html>`
}
