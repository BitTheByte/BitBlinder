# BitBlinder

**Release 0.7**
Burp Suite extension for blind **and reflected** XSS discovery. Injects payloads
into in-scope Proxy traffic, runs sends off the Burp thread on a bounded worker
pool, and analyses responses for canary reflections to surface confirmed
findings with context-aware severity.

```
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
-  Developer: Ahmed Ezzat (BitTheByte)      -
-  Github:    https://github.com/BitTheByte -
-  Version:   0.7                           -
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
[WARNING] EDIT THE SETTINGS BEFORE USE
[WARNING] WORKS ON IN-SCOPE PROXY TRAFFIC ONLY
[WARNING] THIS TOOL CAN GENERATE SIGNIFICANT TRAFFIC
```

## What's new in 0.7

- **Reflected XSS detection** with canary tokens and context-aware severity
  (Critical / High / Medium / Low) — see *How detection works* below.
- **Forward-parse HTML tokenizer** classifies the context around each
  canary occurrence (HTML text, tag body, attribute single/double/unquoted,
  `<script>` body, JS-string single/double-quoted, `<style>`, comment,
  CDATA). Handles multi-attribute tags, attribute values that contain
  nested HTML-like content (`data-text="<b>x</b>"`), and `<script>` blocks
  with embedded quotes — patterns that backward-regex heuristics
  mis-classify.
- **Burp Site Map integration**: every reflection is wrapped with
  `applyMarkers` (request and response) and added to Burp's Site Map, so
  the canary highlights inline in Burp's native message viewer.
- **Async worker pool** (bounded `ThreadPoolExecutor`, per-host concurrency
  cap, `CallerRunsPolicy` back-pressure). Burp's Proxy stays responsive even
  with many payloads.
- **Tabbed UI**: *Settings*, *Activity*, *Findings*. Right-click a finding to
  copy its URL, copy the injected request, or send it to Repeater / Intruder.
- **Findings persistence** across Burp restarts (capped at 1000 newest).
- **CSV export** of findings (RFC 4180).
- **Tool filter** — only Proxy traffic triggers injection. Burp Scanner /
  Repeater / Intruder are no longer affected.
- **Request-fingerprint dedup** with cooldown — refreshing the same page no
  longer floods the target.
- **Body-size cap** — large upload bodies (file uploads etc.) are skipped.
- **Expanded never-inject header set** — `Host`, `Cookie`, `Authorization`,
  `Content-Length`, `Transfer-Encoding`, etc. are never injected into.
- **Extended placeholders**: `$(canary)`, `$(uuid)`, `$(random)`, `$(time)`,
  `$(host)`, `$(param)`.
- **More payload templates**: attribute breakout, JS string breakout, HTML
  comment escape, canary-only probe.
- Lifecycle: extension cleanly shuts down the worker pool and persists
  findings on unload.

## Highlights

- Injects into URL & body parameters, JSON bodies (recursive), and a
  configurable list of header names.
- Detects reflected XSS via canary tokens; classifies context (HTML text,
  attribute quoted/unquoted, `<script>`, `<style>`, comment, header).
- Severity-scored findings with response excerpts and pivots to Repeater /
  Intruder.
- Per-host rate limiting and request-shape deduplication.
- Persistence: settings & findings survive Burp restarts.
- Exclusion lists by host, path prefix, or parameter name.

## Requirements

- Burp Suite
- Jython 2.7 (for Python extensions)

## Install

1. Burp → Extender → Extensions → **Add**.
2. Pick *Python*, point at `blinder.py`.
3. The new **Bit Blinder** tab appears.

## Quick start

1. Open the **Bit Blinder** tab.
2. *Settings* tab → toggle **Enable scanning**, **Detect reflected XSS**.
3. Add or keep a payload that contains `$(canary)` (the default does).
4. Make sure your target is **in scope** (Target → Scope).
5. Browse the app. Watch the *Activity* tab for injections and the
   *Findings* tab for confirmed reflections.

## How detection works

Every outgoing injection has a unique 12-character marker (`bb` + 10 alpha-
numeric chars, ~10^15 collision space). The marker is woven into the payload
via the `$(canary)` placeholder or auto-appended when **Append canary token
to payloads** is on.

After Burp returns the response, the extension:

1. Skips non-text responses (only HTML / XML / JSON / script / plain / css are
   scanned) and bodies larger than 5 MB.
2. Searches the first 2 MB of the body for the marker, byte-level, via
   `helpers.indexOf` (no decoding — multibyte responses match correctly).
3. Forward-parses the body with an HTML tokenizer (state machine over
   tags, attributes, `<script>`/`<style>`, comments, CDATA) to build a
   context map that can be queried in O(log n) by offset. For every
   canary occurrence, it looks up the exact surrounding context:
   `HTML_TEXT`, `TAG`, `ATTR_DQUOTE` / `ATTR_SQUOTE` / `ATTR_UNQUOTED`,
   `SCRIPT`, `SCRIPT_DQUOTE` / `SCRIPT_SQUOTE`, `STYLE`, `COMMENT`,
   or `CDATA`.
4. Also checks response headers for the marker (separate `HEADER_ECHO`
   channel with lower severity).
5. Scores severity:
   - **Critical** — reflection in `<script>` body, tag-body, unquoted
     attribute, or plain HTML text with unencoded `<` introduced by the
     payload. JS-string contexts upgrade to Critical only if the payload
     contains the matching quote character (otherwise Medium).
   - **High** — quoted attribute reflection where the payload contains the
     matching quote character. Header reflections in `Content-Type`,
     `Refresh`, `Location`, `Link`.
   - **Medium** — quoted-attribute reflection without a matching quote,
     reflections in `<style>` / HTML comments / CDATA, HTML-encoded text
     reflections.
   - **Low** — header echoes elsewhere.
6. Wraps the request + response with marker offsets via Burp's
   `applyMarkers` and adds them to Burp's Site Map. The canary then
   highlights inline when you view the entry in Burp's standard message
   viewer. Toggle this with **Mark hits in Site Map**.

The Findings tab shows time, severity, host, method, path, where it was
injected, context, response status / size, payload preview, and the canary.

## Configuration

### Payloads

Line-separated. If **Randomize** is off, only the first is used.

```
"><script>alert(/$(canary)/)</script>
"><svg onload=alert(/$(canary)/)>
```

Use the template picker to insert common patterns.

### Placeholders

| Placeholder   | Replaced with                                          |
|---------------|--------------------------------------------------------|
| `$(canary)`   | Per-injection marker (required for reflected detection)|
| `$(uuid)`     | Fresh random UUID                                      |
| `$(random)`   | 8 lowercase hex chars                                  |
| `$(time)`     | Current time in epoch ms                               |
| `$(host)`     | Target host                                            |
| `$(param)`    | Param / header / JSON path being injected              |

If a payload doesn't contain `$(canary)` and **Append canary token** is on,
the marker is appended automatically so detection still works.

### Encoding

Payloads are auto-URL-encoded by default. Disable **Auto-encode payloads**
for raw injection (Burp's `updateParameter` vs. our raw substitution).

### Options

- **Enable scanning** — master switch.
- **Detect reflected XSS** — scan responses for canary hits.
- **Append canary token to payloads** — keep on unless you know what you're
  doing; without it, reflection detection has nothing to look for.
- **Mark hits in Site Map** — on every reflection, wrap the request/response
  with `applyMarkers` and add the entry to Burp's Site Map. Burp's native
  message viewer then highlights the canary inline.
- **Randomize payloads** — pick a random payload per injection.
- **Auto-encode payloads** — let Burp URL-encode payloads.
- **In-scope only** — process only in-scope items.
- **Inject headers** — also inject into the header names listed below.
- **Inject JSON body** — inject into JSON bodies.
- **JSON: only string values** — skip non-string JSON leaves.
- **Verbose activity** — show payload details in the status line.

### Performance / safety

- **Rate (ms/host)** — minimum gap between injection requests for the same
  host:port (0 = off).
- **Dedup (ms)** — cooldown for identical request shapes
  (method + host + path + param-name-set + inject-modes). 0 = disabled.
- **Workers** — async worker thread count.
- **Queue** — max queued injections. On overflow we use
  `CallerRunsPolicy`: the Proxy listener thread does the send, naturally
  throttling browsing instead of throwing.
- **Per-host** — max concurrent in-flight injections per host.
- **Max body** — bytes. Requests with bodies larger than this aren't
  injected into (avoids file-upload corruption).

### Exclusions

Hosts (exact or subdomain), Paths (prefix), Params (exact name).

### Storage

- Settings: Burp extension storage, key `bitblinder.config` (version 2).
- Findings: Burp extension storage, key `bitblinder.findings` (capped at
  1000 newest, request bodies capped at 64 KB each).

## How injection works

Visiting `https://example.com?a=1&b=2` produces (in the background):

1. `https://example.com?a=<PAYLOAD>&b=2`
2. `https://example.com?a=1&b=<PAYLOAD>`

Same logic for POST params and JSON bodies (if enabled). Each request gets a
fresh canary and an `X-Blinder-Ignore: yes` header so we never inject our own
injection requests.

## Findings table

| Action                        | How                                |
|-------------------------------|------------------------------------|
| Filter rows                   | Type into the *Filter* box (regex) |
| Sort                          | Click a column header              |
| Copy URL                      | Right-click → Copy URL             |
| Copy payload                  | Right-click → Copy payload         |
| Copy injected request (curl)  | Right-click → Copy as curl         |
| Replay in Repeater            | Right-click → Send to Repeater     |
| Replay in Intruder            | Right-click → Send to Intruder     |
| Mark as false positive        | Right-click → Mark / unmark FP     |
| Delete a row                  | Right-click → Delete row           |
| Export to CSV                 | *Export CSV* button                |
| Clear all                     | *Clear findings* button            |

## Notes

- Generates significant traffic — expect rate-limits / WAF blocks on real
  targets. Tune **Rate** and **Per-host** accordingly.
- Runs on Proxy traffic only. Use Burp Scanner separately; BitBlinder won't
  interfere with active scans.
- Requests are sent through Burp's HTTP engine and appear in the Site Map
  (tagged via `X-Blinder-Ignore`).
- Reflection detection is a heuristic. Treat **Critical** findings as
  likely-exploitable, but always confirm manually in Repeater.

## Troubleshooting

- **No activity**: target not in scope, or extension disabled.
- **No injections**: empty payload list or all params excluded.
- **No reflections found** but reflection clearly happens: WAF may strip the
  canary, response may be encoded (canary in `&lt;...&gt;`), or response is
  binary / oversized (we skip > 5 MB).
- **Findings tab missing rows after restart**: persistence is capped at
  1000 newest; older entries are dropped.
- **Burp UI lag under heavy injection**: lower **Workers** or **Queue**, or
  increase **Per-host** + **Rate**.

## Compatibility

- Burp Suite Community / Professional with the Jython extension loaded.
- Tested against Jython 2.7.x.
