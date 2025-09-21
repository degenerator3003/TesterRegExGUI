#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regex Tester GUI (pure Python 3.10, stdlib only)

Now with a third tab: a **visual regex builder**.
- Left: token chooser (add literals, classes, anchors, alternation, groups, lookarounds, raw snippets).
- Center: sequence list with move up/down, remove, wrap selection in groups/lookarounds, apply quantifiers.
- Right: live preview, flags, compile status, "Send to Tester", and "Save as preset".

Author: You
"""

import json
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# ----------------------------- Presets ---------------------------------------
# Add/extend patterns here. Target ~250 comfortably; kept shorter here.
# Format: ("Descriptive Name", r"your_pattern")
BUILTIN_PATTERNS: list[tuple[str, str]] = [
    # ---- Emails / Users ----
    ("Email (loose)", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("Email (strict-ish)", r"(?:(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*)|"
                           r"\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@"
                           r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}|"
                           r"\[(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\])"),
    ("Username (alnum/._-)", r"[A-Za-z0-9._-]{3,32}"),

    # ---- URLs / URIs ----
    ("URL (http/https)", r"https?://[^\s/$.?#].[^\s]*"),
    ("URL (with path/query)", r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s?#]*)?(?:\?[^\s#]*)?(?:#[^\s]*)?"),
    ("Domain", r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"),
    ("IPv4 URL", r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?"),

    # ---- IP / Net ----
    ("IPv4 (0-255 aware)", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
    ("IPv6 (simple)", r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"),
    ("MAC (colon)", r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"),
    ("MAC (dash)", r"\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b"),
    ("CIDR IPv4", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:[0-9]|[12]\d|3[0-2])\b"),

    # ---- Dates / Times ----
    ("Date YYYY-MM-DD", r"\b\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b"),
    ("Date DD/MM/YYYY", r"\b(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/\d{4}\b"),
    ("Time HH:MM", r"\b([01]\d|2[0-3]):([0-5]\d)\b"),
    ("Time HH:MM:SS", r"\b([01]\d|2[0-3]):([0-5]\d):([0-5]\d)\b"),
    ("ISO 8601 datetime", r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"),

    # ---- Numbers / Money ----
    ("Integer", r"[+-]?\b\d+\b"),
    ("Float", r"[+-]?(?:\d+\.\d+|\d+\.|\.\d+)(?:[eE][+-]?\d+)?"),
    ("Currency ($1,234.56)", r"\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?"),
    ("Percent", r"\b\d+(?:\.\d+)?%"),

    # ---- Colors / IDs ----
    ("Hex color #RRGGBB", r"#(?:[A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})\b"),
    ("UUID v4", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
    ("GUID (any)", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),

    # ---- Files / Paths ----
    ("Windows path", r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
    ("POSIX path", r"(?:/[^/\s]+)+/?"),

    # ---- Code-ish / Markup ----
    ("HTML tag", r"</?[A-Za-z][A-Za-z0-9-]*(?:\s+[^\s<>/=]+(?:=(?:\"[^\"]*\"|'[^']*'|[^\s'\">=]+))?)*\s*/?>"),
    ("HTML comment", r"<!--[\s\S]*?-->"),
    ("XML/HTML entity", r"&[A-Za-z0-9#]+;"),
    ("JSON key", r"\"([^\"]+)\"\s*:"),
    ("C-style comment", r"/\*[\s\S]*?\*/"),
    ("Line comment (//...)", r"//[^\n]*"),
    ("Python identifier", r"\b[A-Za-z_][A-Za-z0-9_]*\b"),

    # ---- Words ----
    ("Word (letters only)", r"\b[A-Za-z]+\b"),
    ("Word (unicode-ish)", r"\b[^\W\d_]+\b"),
    ("Hashtag", r"#\w+"),
    ("Mention @", r"@\w+"),

    # ---- Phones ----
    ("Phone (intl-ish)", r"\+?\d[\d\s().-]{6,}\d"),
    ("US phone (strict-ish)", r"\b(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"),

    # ---- Misc ----
    ("Postal Code (US ZIP)", r"\b\d{5}(?:-\d{4})?\b"),
    ("Credit Card (loose)", r"\b(?:\d[ -]*?){13,19}\b"),
    ("SHA-1", r"\b[a-fA-F0-9]{40}\b"),
    ("SHA-256", r"\b[a-fA-F0-9]{64}\b"),
    ("IBAN (loose)", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    ("Bitcoin address (legacy/P2SH)", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    ("Base64 chunk", r"\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"),

    # ---- Brackets / Quotes ----
    ("Balanced parentheses (non-nested)", r"\([^()]*\)"),
    ("Quoted string (double)", r"\"(?:\\.|[^\"\\])*\""),
    ("Quoted string (single)", r"'(?:\\.|[^'\\])*'"),

    # ---- Logs ----
    ("Syslog timestamp", r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b"),
    ("Apache/Nginx log date", r"\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"),
    ("HTTP status line", r"HTTP/\d\.\d\s+\d{3}\s+[^\r\n]*"),

    # ---- CSV/TSV ----
    ("CSV field (quoted)", r"\"(?:\"\"|[^\"])*\""),
    ("CSV field (unquoted)", r"[^,\r\n]*"),

    # ---- International ----
    ("Cyrillic word", r"\b[А-Яа-яЁё]+\b"),
    ("Greek word", r"\b[Α-Ωα-ω]+\b"),

    # ---- Anchors / boundaries ----
    ("Start of line", r"^"),
    ("End of line", r"$"),
    ("Word boundary \\b", r"\b"),

    # ---- Password-ish (demo) ----
    ("Password (>=8 letters+number)", r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}"),

    # ---- HTML attributes ----
    ("HTML src=... value", r"\bsrc=(\"[^\"]*\"|'[^']*'|[^\s>]+)"),
    ("HTML href=... value", r"\bhref=(\"[^\"]*\"|'[^']*'|[^\s>]+)"),

    # ---- Markdown ----
    ("Markdown link [text](url)", r"\[[^\]]+\]\([^)]+\)"),
    ("Markdown code fence ```...```", r"```[\s\S]*?```"),
    ("Markdown inline `code`", r"`[^`\n]+`"),
]

# A few long sample texts to test against quickly.
SAMPLE_TEXTS: dict[str, str] = {
    "Mixed (emails, URLs, IPv4)": """\
Contact us at support@example.com or admin@mail.example.org.
Visit https://example.com or http://sub.example.co.uk:8080/path?q=1#frag
Server IPs: 10.0.0.1, 192.168.0.250 and 255.255.255.255. Bad: 999.1.1.1
MACs: ab:cd:ef:12:34:56 and AA-BB-CC-11-22-33
""",
    "JSON-like": """\
{
  "user": "alice_01",
  "email": "alice@example.com",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "color": "#1a2b3c",
  "url": "https://api.example.com/v1/users?active=true",
  "created_at": "2025-09-20T12:34:56Z"
}
""",
    "HTML snippet": """\
<!-- a comment -->
<a href="https://example.org">link</a>
<img src='/img/logo.png' alt="logo">
<code>printf("hi");</code>
""",
    "Logs": """\
Sep 15 13:45:12 host sshd[1234]: Failed password for invalid user root from 203.0.113.42 port 2222 ssh2
127.0.0.1 - - [20/Sep/2025:09:12:33 +0600] "GET /index.html HTTP/1.1" 200 1234
"""
}

# ----------------------------- App -------------------------------------------

class RegexTesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Regular Expression Tester")
        self.geometry("1180x760")

        # Data
        self.patterns: list[dict] = [{"name": n, "regex": p} for n, p in BUILTIN_PATTERNS]

        # Fonts
        self.font_mono = ("Courier New", 11)
        self.font_ui = ("Segoe UI", 10)

        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self.tester_tab = ttk.Frame(self.nb)
        self.table_tab = ttk.Frame(self.nb)
        self.builder_tab = ttk.Frame(self.nb)
        self.nb.add(self.tester_tab, text="Tester")
        self.nb.add(self.table_tab, text="Patterns")
        self.nb.add(self.builder_tab, text="Builder")

        self._build_menu()
        self._build_tester()
        self._build_table()
        self._build_builder()

    # ---------- Menu ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        filem = tk.Menu(menubar, tearoff=False)
        filem.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filem)

        presetm = tk.Menu(menubar, tearoff=False)
        presetm.add_command(label="Export presets…", command=self.export_presets)
        presetm.add_command(label="Import presets…", command=self.import_presets)
        menubar.add_cascade(label="Presets", menu=presetm)

        helpm = tk.Menu(menubar, tearoff=False)
        helpm.add_command(label="About", command=lambda: messagebox.showinfo(
            "About", "Regex Tester GUI\nPure Python 3.10 (Tkinter + re)"))
        menubar.add_cascade(label="Help", menu=helpm)

    # ---------- Tester UI ----------
    def _build_tester(self):
        outer = ttk.Frame(self.tester_tab)
        outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Top: preset selection above regex entry
        top = ttk.Frame(outer)
        top.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top, text="Pattern preset:").pack(side=tk.LEFT)
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(
            top, textvariable=self.preset_var, values=[p["name"] for p in self.patterns], state="readonly", width=45)
        self.preset_combo.pack(side=tk.LEFT, padx=6)
        self.preset_combo.bind("<<ComboboxSelected>>", self.on_preset_selected)

        # Regex entry
        regex_row = ttk.Frame(outer)
        regex_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(regex_row, text="Regular expression:").pack(side=tk.LEFT)
        self.regex_var = tk.StringVar()
        self.regex_entry = ttk.Entry(regex_row, textvariable=self.regex_var)
        self.regex_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)

        # Flags
        flags_row = ttk.Frame(outer)
        flags_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(flags_row, text="Flags:").pack(side=tk.LEFT)
        self.flag_ic = tk.BooleanVar(value=False)   # IGNORECASE
        self.flag_ml = tk.BooleanVar(value=False)   # MULTILINE
        self.flag_ds = tk.BooleanVar(value=False)   # DOTALL
        self.flag_vb = tk.BooleanVar(value=False)   # VERBOSE
        self.flag_ai = tk.BooleanVar(value=False)   # ASCII
        ttk.Checkbutton(flags_row, text="IGNORECASE", variable=self.flag_ic).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_row, text="MULTILINE", variable=self.flag_ml).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_row, text="DOTALL", variable=self.flag_ds).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_row, text="VERBOSE", variable=self.flag_vb).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_row, text="ASCII", variable=self.flag_ai).pack(side=tk.LEFT, padx=4)

        # Samples + buttons
        btn_row = ttk.Frame(outer)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(btn_row, text="Sample text:").pack(side=tk.LEFT)
        self.sample_var = tk.StringVar(value="(none)")
        sample_values = ["(none)"] + list(SAMPLE_TEXTS.keys())
        self.sample_combo = ttk.Combobox(btn_row, textvariable=self.sample_var,
                                         values=sample_values, state="readonly", width=32)
        self.sample_combo.pack(side=tk.LEFT, padx=6)
        self.sample_combo.bind("<<ComboboxSelected>>", self.on_sample_selected)

        ttk.Button(btn_row, text="Find", command=self.on_find).pack(side=tk.RIGHT)
        ttk.Button(btn_row, text="Clear Results", command=self.clear_results).pack(side=tk.RIGHT, padx=(0, 6))

        # Split: Text (left) and Results (right)
        paned = ttk.PanedWindow(outer, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Text area
        text_frame = ttk.Frame(paned)
        paned.add(text_frame, weight=3)
        self.text = tk.Text(text_frame, wrap="word", font=self.font_mono, undo=True)
        yscroll = ttk.Scrollbar(text_frame, command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.text.tag_configure("match", background="#ffe599")

        # Results list
        result_frame = ttk.Frame(paned)
        paned.add(result_frame, weight=2)
        ttk.Label(result_frame, text="Found matches").pack(anchor="w")
        self.results = tk.Listbox(result_frame, activestyle="dotbox")
        self.results.pack(fill=tk.BOTH, expand=True)
        self.results.bind("<Double-Button-1>", self.on_result_double)

    # ---------- Patterns table ----------
    def _build_table(self):
        outer = ttk.Frame(self.table_tab)
        outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Search/filter
        filter_row = ttk.Frame(outer)
        filter_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(filter_row, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        ent = ttk.Entry(filter_row, textvariable=self.filter_var)
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ent.bind("<KeyRelease>", lambda e: self.refresh_table())

        # Table
        self.tree = ttk.Treeview(outer, columns=("name", "regex"), show="headings")
        self.tree.heading("name", text="Name")
        self.tree.heading("regex", text="RegExp")
        self.tree.column("name", width=240, anchor="w")
        self.tree.column("regex", width=850, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<<TreeviewSelect>>", self.on_table_select)
        self.refresh_table()

    # ---------- Builder tab ----------
    def _build_builder(self):
        outer = ttk.Frame(self.builder_tab)
        outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.builder_tokens: list[str] = []  # flat list of snippets making the regex

        # Three columns using PanedWindow
        paned = ttk.PanedWindow(outer, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: token palette
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Token palette").pack(anchor="w")

        self.token_var = tk.StringVar(value="Literal")
        token_types = [
            "Literal", "Raw snippet", "Any .",
            "Digit \\d", "Non-digit \\D",
            "Word \\w", "Non-word \\W",
            "Whitespace \\s", "Non-whitespace \\S",
            "Tab \\t", "Newline \\n", "Carriage \\r",
            "Boundary \\b", "Non-boundary \\B",
            "Start ^", "End $", "Start string \\A", "End string \\Z",
            "Class [chars]", "Negated class [^chars]",
            "Predef [A-Z]", "Predef [a-z]", "Predef [0-9]",
            "Predef [A-Za-z]", "Predef [A-Za-z0-9_]", 
            "Alternation |",
            "Wrap: (group)", "Wrap: (?:non-capturing)", "Wrap: (?P<name>group)",
            "Wrap: (?=lookahead)", "Wrap: (?!neg lookahead)",
            "Wrap: (?<=lookbehind)", "Wrap: (?<!neg lookbehind)",
            "Backreference \\1…"
        ]
        self.token_combo = ttk.Combobox(left, textvariable=self.token_var, values=token_types, state="readonly", width=28)
        self.token_combo.pack(fill=tk.X, pady=4)

        ttk.Button(left, text="Add token", command=self.builder_add_token).pack(fill=tk.X, pady=2)

        ttk.Separator(left).pack(fill=tk.X, pady=6)

        ttk.Label(left, text="Quantifier").pack(anchor="w")
        self.q_var = tk.StringVar(value="(none)")
        quant_values = ["(none)", "?", "*", "+", "{n}", "{min,}", "{min,max}"]
        self.q_combo = ttk.Combobox(left, textvariable=self.q_var, values=quant_values, state="readonly", width=12)
        self.q_combo.pack(fill=tk.X, pady=2)
        self.q_lazy = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Lazy (add '?')", variable=self.q_lazy).pack(anchor="w")
        ttk.Button(left, text="Apply to selection", command=self.builder_apply_quantifier).pack(fill=tk.X, pady=2)

        ttk.Separator(left).pack(fill=tk.X, pady=6)
        ttk.Label(left, text="Suggestions").pack(anchor="w")
        self.sugg_var = tk.StringVar(value="(none)")
        sugg_values = ["(none)", "Email (loose)", "IPv4 (0-255 aware)", "Date YYYY-MM-DD", "Quoted string (double)"]
        self.sugg_combo = ttk.Combobox(left, textvariable=self.sugg_var, values=sugg_values, state="readonly")
        self.sugg_combo.pack(fill=tk.X, pady=2)
        ttk.Button(left, text="Insert suggestion", command=self.builder_insert_suggestion).pack(fill=tk.X, pady=2)

        # Center: sequence list + controls
        center = ttk.Frame(paned)
        paned.add(center, weight=2)
        ttk.Label(center, text="Regex sequence (tokens)").pack(anchor="w")

        self.seq_list = tk.Listbox(center, activestyle="dotbox")
        self.seq_list.pack(fill=tk.BOTH, expand=True)
        ctrls = ttk.Frame(center)
        ctrls.pack(fill=tk.X, pady=4)
        ttk.Button(ctrls, text="Up", command=lambda: self.builder_move(-1)).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrls, text="Down", command=lambda: self.builder_move(+1)).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrls, text="Remove", command=self.builder_remove).pack(side=tk.LEFT, padx=6)
        ttk.Button(ctrls, text="Clear all", command=self.builder_clear).pack(side=tk.LEFT, padx=2)

        # Right: preview + flags + actions
        right = ttk.Frame(paned)
        paned.add(right, weight=2)
        ttk.Label(right, text="Live preview").pack(anchor="w")
        self.preview = tk.Text(right, height=5, font=self.font_mono, wrap="none")
        self.preview.pack(fill=tk.X, pady=2)
        self.preview.configure(state="disabled")

        self.compile_lbl = ttk.Label(right, text="")
        self.compile_lbl.pack(anchor="w")

        flags_frame = ttk.Frame(right)
        flags_frame.pack(fill=tk.X, pady=4)
        ttk.Label(flags_frame, text="Flags:").pack(side=tk.LEFT)
        self.b_flag_ic = tk.BooleanVar(value=False)
        self.b_flag_ml = tk.BooleanVar(value=False)
        self.b_flag_ds = tk.BooleanVar(value=False)
        self.b_flag_vb = tk.BooleanVar(value=False)
        self.b_flag_ai = tk.BooleanVar(value=False)
        ttk.Checkbutton(flags_frame, text="IGNORECASE", variable=self.b_flag_ic, command=self.builder_update_preview).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_frame, text="MULTILINE", variable=self.b_flag_ml, command=self.builder_update_preview).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_frame, text="DOTALL", variable=self.b_flag_ds, command=self.builder_update_preview).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_frame, text="VERBOSE", variable=self.b_flag_vb, command=self.builder_update_preview).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(flags_frame, text="ASCII", variable=self.b_flag_ai, command=self.builder_update_preview).pack(side=tk.LEFT, padx=4)

        act = ttk.Frame(right)
        act.pack(fill=tk.X, pady=6)
        ttk.Button(act, text="Send to Tester", command=self.builder_send_to_tester).pack(side=tk.LEFT, padx=2)
        ttk.Button(act, text="Save as preset…", command=self.builder_save_preset).pack(side=tk.LEFT, padx=6)
        ttk.Button(act, text="Copy regex", command=self.builder_copy_regex).pack(side=tk.LEFT, padx=2)

        # Tokens detail
        ttk.Label(right, text="Tokens (joined for preview above):").pack(anchor="w", pady=(8,0))
        self.tokens_view = tk.Text(right, height=8, font=self.font_mono, wrap="word")
        self.tokens_view.pack(fill=tk.BOTH, expand=True)
        self.tokens_view.configure(state="disabled")

    # ---------- Helpers (common) ----------
    def build_flags(self) -> int:
        flags = 0
        if self.flag_ic.get():
            flags |= re.IGNORECASE
        if self.flag_ml.get():
            flags |= re.MULTILINE
        if self.flag_ds.get():
            flags |= re.DOTALL
        if self.flag_vb.get():
            flags |= re.VERBOSE
        if self.flag_ai.get():
            flags |= re.ASCII
        return flags

    # ---------- Tester handlers ----------
    def on_preset_selected(self, _event=None):
        name = self.preset_var.get()
        for p in self.patterns:
            if p["name"] == name:
                self.regex_var.set(p["regex"])
                self.regex_entry.icursor(tk.END)
                break

    def on_sample_selected(self, _event=None):
        key = self.sample_var.get()
        self.text.tag_remove("match", "1.0", tk.END)
        if key == "(none)":
            return
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", SAMPLE_TEXTS.get(key, ""))

    def clear_results(self):
        self.results.delete(0, tk.END)
        self.text.tag_remove("match", "1.0", tk.END)

    def on_find(self):
        pattern = self.regex_var.get()
        self.clear_results()
        if not pattern:
            messagebox.showwarning("No regex", "Please enter a regular expression.")
            return
        try:
            regex = re.compile(pattern, self.build_flags())
        except re.error as e:
            messagebox.showerror("Regex error", f"Invalid pattern:\n{e}")
            return

        content = self.text.get("1.0", tk.END)
        count = 0
        for m in regex.finditer(content):
            start, end = m.span()
            match_text = m.group(0)
            disp = match_text if len(match_text) <= 80 else match_text[:77] + "..."
            self.results.insert(tk.END, f"{disp!r} @ [{start}:{end}]")
            self._highlight_span(start, end)
            count += 1

        if count == 0:
            self.results.insert(tk.END, "(no matches)")

    def _highlight_span(self, start_idx: int, end_idx: int):
        self.text.tag_add("match", f"1.0 + {start_idx} chars", f"1.0 + {end_idx} chars")

    def on_result_double(self, _event=None):
        sel = self.results.curselection()
        if not sel:
            return
        line = self.results.get(sel[0])
        if "@ [" not in line:
            return
        try:
            span = line.split("@ [", 1)[1].rstrip("]")
            start_s, end_s = span.split(":")
            start, end = int(start_s), int(end_s)
        except Exception:
            return
        self.text.see(f"1.0 + {start} chars")
        self.text.tag_remove("match", "1.0", tk.END)
        self._highlight_span(start, end)

    def refresh_table(self):
        q = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        for p in self.patterns:
            if not q or q in p["name"].lower() or q in p["regex"].lower():
                self.tree.insert("", tk.END, values=(p["name"], p["regex"]))

    def on_table_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        name, regex = self.tree.item(sel[0], "values")
        self.regex_var.set(regex)
        self.preset_var.set(name)

    # ---------- Import/Export ----------
    def export_presets(self):
        path = filedialog.asksaveasfilename(
            title="Export presets", defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            data = [{"name": p["name"], "regex": p["regex"]} for p in self.patterns]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Export", f"Exported {len(self.patterns)} presets.")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def import_presets(self):
        path = filedialog.askopenfilename(
            title="Import presets", filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Validate + merge (dedupe by name)
            seen = {p["name"] for p in self.patterns}
            added = 0
            for item in data:
                name = str(item.get("name", "")).strip()
                regex = str(item.get("regex", ""))
                if not name or not regex:
                    continue
                if name in seen:
                    # Replace existing with same name
                    for p in self.patterns:
                        if p["name"] == name:
                            p["regex"] = regex
                            break
                else:
                    self.patterns.append({"name": name, "regex": regex})
                    seen.add(name)
                    added += 1
            self.preset_combo["values"] = [p["name"] for p in self.patterns]
            self.refresh_table()
            messagebox.showinfo("Import", f"Imported. New added: {added}. Total: {len(self.patterns)}")
        except Exception as e:
            messagebox.showerror("Import error", str(e))

    # ====================== Builder logic =====================================
    @staticmethod
    def _escape_literal(s: str) -> str:
        """Escape a literal for use in a regex (outside of char classes)."""
        return re.escape(s)

    @staticmethod
    def _escape_charclass(s: str) -> str:
        """Escape inside [...] where ^ - ] \ need special care."""
        out = []
        for ch in s:
            if ch in r"\^-]":
                out.append("\\" + ch)
            else:
                out.append(ch)
        return "".join(out)

    def builder_add_token(self):
        kind = self.token_var.get()
        add = None

        if kind == "Literal":
            s = simpledialog.askstring("Literal", "Enter literal text (will be escaped):", parent=self)
            if s is None:
                return
            add = self._escape_literal(s)

        elif kind == "Raw snippet":
            s = simpledialog.askstring("Raw snippet", "Enter raw regex (no escaping):", parent=self)
            if s is None:
                return
            add = s

        elif kind == "Any .":
            add = "."
        elif kind == "Digit \\d":
            add = r"\d"
        elif kind == "Non-digit \\D":
            add = r"\D"
        elif kind == "Word \\w":
            add = r"\w"
        elif kind == "Non-word \\W":
            add = r"\W"
        elif kind == "Whitespace \\s":
            add = r"\s"
        elif kind == "Non-whitespace \\S":
            add = r"\S"
        elif kind == "Tab \\t":
            add = r"\t"
        elif kind == "Newline \\n":
            add = r"\n"
        elif kind == "Carriage \\r":
            add = r"\r"
        elif kind == "Boundary \\b":
            add = r"\b"
        elif kind == "Non-boundary \\B":
            add = r"\B"
        elif kind == "Start ^":
            add = r"^"
        elif kind == "End $":
            add = r"$"
        elif kind == "Start string \\A":
            add = r"\A"
        elif kind == "End string \\Z":
            add = r"\Z"
        elif kind == "Class [chars]":
            s = simpledialog.askstring("Character class", "Characters to include:", parent=self)
            if s is None:
                return
            add = "[" + self._escape_charclass(s) + "]"
        elif kind == "Negated class [^chars]":
            s = simpledialog.askstring("Negated class", "Characters to exclude:", parent=self)
            if s is None:
                return
            add = "[^" + self._escape_charclass(s) + "]"
        elif kind == "Predef [A-Z]":
            add = "[A-Z]"
        elif kind == "Predef [a-z]":
            add = "[a-z]"
        elif kind == "Predef [0-9]":
            add = "[0-9]"
        elif kind == "Predef [A-Za-z]":
            add = "[A-Za-z]"
        elif kind == "Predef [A-Za-z0-9_]":
            add = r"[A-Za-z0-9_]"
        elif kind == "Alternation |":
            add = "|"
        elif kind.startswith("Wrap: "):
            self.builder_wrap(kind)
            return
        elif kind == "Backreference \\1…":
            num = simpledialog.askinteger("Backreference", "Group number (1..99):", minvalue=1, maxvalue=99, parent=self)
            if num is None:
                return
            add = "\\" + str(num)

        if add is not None:
            self.builder_tokens.append(add)
            self.seq_list.insert(tk.END, add)
            self.builder_update_preview()

    def builder_move(self, delta: int):
        sel = list(self.seq_list.curselection())
        if not sel:
            return
        i = sel[0]
        j = i + delta
        if j < 0 or j >= len(self.builder_tokens):
            return
        self.builder_tokens[i], self.builder_tokens[j] = self.builder_tokens[j], self.builder_tokens[i]
        self.seq_list.delete(0, tk.END)
        for t in self.builder_tokens:
            self.seq_list.insert(tk.END, t)
        self.seq_list.selection_set(j)
        self.builder_update_preview()

    def builder_remove(self):
        sel = list(self.seq_list.curselection())
        if not sel:
            return
        i = sel[0]
        del self.builder_tokens[i]
        self.seq_list.delete(i)
        self.builder_update_preview()

    def builder_clear(self):
        self.builder_tokens.clear()
        self.seq_list.delete(0, tk.END)
        self.builder_update_preview()

    def builder_selected_slice(self):
        """Return (start,end) inclusive indices for current selection in listbox; if none, returns (None,None)."""
        sel = list(self.seq_list.curselection())
        if not sel:
            return None, None
        start = sel[0]
        end = sel[-1]
        return start, end

    def builder_apply_quantifier(self):
        q = self.q_var.get()
        if q == "(none)":
            return
        s, e = self.builder_selected_slice()
        if s is None:
            messagebox.showinfo("Selection needed", "Select at least one token to quantify.")
            return

        # Build quantifier suffix
        suffix = ""
        if q in ("?", "*", "+"):
            suffix = q
        elif q == "{n}":
            n = simpledialog.askinteger("Exactly n", "n =", minvalue=0, parent=self)
            if n is None:
                return
            suffix = "{" + str(n) + "}"
        elif q == "{min,}":
            n = simpledialog.askinteger("At least min", "min =", minvalue=0, parent=self)
            if n is None:
                return
            suffix = "{" + str(n) + ",}"
        elif q == "{min,max}":
            minv = simpledialog.askinteger("Range", "min =", minvalue=0, parent=self)
            if minv is None:
                return
            maxv = simpledialog.askinteger("Range", "max =", minvalue=minv, parent=self)
            if maxv is None:
                return
            suffix = "{" + str(minv) + "," + str(maxv) + "}"

        if self.q_lazy.get():
            suffix += "?"

        # Wrap selection in a non-capturing group then append quantifier
        inner = "".join(self.builder_tokens[s:e+1])
        newtok = "(?:" + inner + ")" + suffix
        # replace slice with single token
        self.builder_tokens[s:e+1] = [newtok]
        # refresh listbox
        self.seq_list.delete(0, tk.END)
        for t in self.builder_tokens:
            self.seq_list.insert(tk.END, t)
        self.seq_list.selection_set(s)
        self.builder_update_preview()

    def builder_wrap(self, kind: str):
        s, e = self.builder_selected_slice()
        if s is None:
            messagebox.showinfo("Selection needed", "Select a range of tokens to wrap.")
            return
        inner = "".join(self.builder_tokens[s:e+1])

        if kind == "Wrap: (group)":
            newtok = "(" + inner + ")"
        elif kind == "Wrap: (?:non-capturing)":
            newtok = "(?:" + inner + ")"
        elif kind == "Wrap: (?P<name>group)":
            name = simpledialog.askstring("Named group", "Group name:", parent=self)
            if not name:
                return
            # simple validation of name
            if not re.match(r"^[A-Za-z_]\w*$", name):
                messagebox.showerror("Invalid name", "Name must match [A-Za-z_]\\w*")
                return
            newtok = "(?P<" + name + ">" + inner + ")"
        elif kind == "Wrap: (?=lookahead)":
            newtok = "(?=" + inner + ")"
        elif kind == "Wrap: (?!neg lookahead)":
            newtok = "(?!" + inner + ")"
        elif kind == "Wrap: (?<=lookbehind)":
            newtok = "(?<=" + inner + ")"
        elif kind == "Wrap: (?<!neg lookbehind)":
            newtok = "(?<!" + inner + ")"
        else:
            return

        self.builder_tokens[s:e+1] = [newtok]
        self.seq_list.delete(0, tk.END)
        for t in self.builder_tokens:
            self.seq_list.insert(tk.END, t)
        self.seq_list.selection_set(s)
        self.builder_update_preview()

    def builder_insert_suggestion(self):
        name = self.sugg_var.get()
        if name == "(none)":
            return
        # Map to existing BUILTIN_PATTERNS by name where possible
        lookup = {p["name"]: p["regex"] for p in self.patterns}
        if name in lookup:
            self.builder_tokens.append(lookup[name])
            self.seq_list.insert(tk.END, lookup[name])
            self.builder_update_preview()
        else:
            messagebox.showwarning("Not found", f"No suggestion named '{name}'.")

    def builder_regex_string(self) -> str:
        return "".join(self.builder_tokens)

    def _builder_flags(self) -> int:
        flags = 0
        if self.b_flag_ic.get():
            flags |= re.IGNORECASE
        if self.b_flag_ml.get():
            flags |= re.MULTILINE
        if self.b_flag_ds.get():
            flags |= re.DOTALL
        if self.b_flag_vb.get():
            flags |= re.VERBOSE
        if self.b_flag_ai.get():
            flags |= re.ASCII
        return flags

    def builder_update_preview(self):
        pattern = self.builder_regex_string()
        # preview text
        self.preview.configure(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", pattern)
        self.preview.configure(state="disabled")

        # tokens view
        self.tokens_view.configure(state="normal")
        self.tokens_view.delete("1.0", tk.END)
        if self.builder_tokens:
            lines = [f"{i+1:>2}: {tok}" for i, tok in enumerate(self.builder_tokens)]
            self.tokens_view.insert("1.0", "\n".join(lines))
        self.tokens_view.configure(state="disabled")

        # compile status
        try:
            re.compile(pattern, self._builder_flags())
            self.compile_lbl.configure(text="✓ Compiles OK", foreground="green")
        except re.error as e:
            self.compile_lbl.configure(text=f"✗ Regex error: {e}", foreground="red")

    def builder_send_to_tester(self):
        pat = self.builder_regex_string()
        self.regex_var.set(pat)
        # push flags as well
        self.flag_ic.set(self.b_flag_ic.get())
        self.flag_ml.set(self.b_flag_ml.get())
        self.flag_ds.set(self.b_flag_ds.get())
        self.flag_vb.set(self.b_flag_vb.get())
        self.flag_ai.set(self.b_flag_ai.get())
        self.nb.select(self.tester_tab)

    def builder_save_preset(self):
        pat = self.builder_regex_string()
        if not pat:
            messagebox.showinfo("Empty", "Nothing to save.")
            return
        name = simpledialog.askstring("Save as preset", "Preset name:", parent=self)
        if not name:
            return
        # Upsert by name
        for p in self.patterns:
            if p["name"] == name:
                p["regex"] = pat
                break
        else:
            self.patterns.append({"name": name, "regex": pat})
        # refresh UI
        self.preset_combo["values"] = [p["name"] for p in self.patterns]
        self.refresh_table()
        self.preset_var.set(name)
        messagebox.showinfo("Saved", f"Preset '{name}' saved.")

    def builder_copy_regex(self):
        pat = self.builder_regex_string()
        self.clipboard_clear()
        self.clipboard_append(pat)
        self.update()  # now it stays in clipboard
        messagebox.showinfo("Copied", "Regex copied to clipboard.")

# ----------------------------- main ------------------------------------------

def main():
    app = RegexTesterApp()
    # Pre-load a default preset and sample
    if app.patterns:
        app.preset_var.set(app.patterns[0]["name"])
        app.regex_var.set(app.patterns[0]["regex"])
    app.mainloop()


if __name__ == "__main__":
    main()
