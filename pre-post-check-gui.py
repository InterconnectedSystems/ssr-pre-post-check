#!/usr/bin/env python3
"""
SSR Pre/Post Check Tool — GUI Version
Juniper Conductor API pre/post change verification

Dependencies: requests (pip install requests)
All other imports are stdlib.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import queue
import csv
import ctypes
import gc
import requests
import json
import urllib3
import os
import argparse
from datetime import datetime
from collections import defaultdict
import difflib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Secure memory helpers
# ---------------------------------------------------------------------------

def _secure_erase(s: str) -> None:
    """
    Best-effort CPython-specific overwrite of a string's internal buffer.
    Python strings are immutable and interned, so this cannot be guaranteed,
    but it reduces the window during which the plaintext sits in memory.
    Falls back silently on non-CPython runtimes.
    """
    if not isinstance(s, str) or not s:
        return
    try:
        # CPython str object layout: ob_refcnt, ob_type, ob_hash, ob_size,
        # ob_state, ob_wstr, then the character data.
        # sys.getsizeof gives the full allocation; we write zeros over the
        # variable-length character data via a char array cast.
        import sys
        size = sys.getsizeof(s)
        buf  = (ctypes.c_char * size).from_address(id(s))
        # Preserve the first ~56 bytes of object header so CPython doesn't
        # segfault on deallocation; only wipe the character payload.
        header = min(56, size)
        ctypes.memset(ctypes.addressof(buf) + header, 0, max(0, size - header))
    except Exception:
        pass  # Non-CPython or layout changed — fail silently

# ---------------------------------------------------------------------------
# Theme constants (Catppuccin-inspired dark palette)
# ---------------------------------------------------------------------------

BG      = "#2b2b3b"
BG2     = "#1e1e2e"
FG      = "#cdd6f4"
ACCENT  = "#89b4fa"
GREEN   = "#a6e3a1"
RED     = "#f38ba8"
YELLOW  = "#f9e2af"
GRAY    = "#6c7086"
ENTRY   = "#313244"
BTN     = "#45475a"

# ---------------------------------------------------------------------------
# Check registry — key: (label, endpoint_type, endpoint_template)
# endpoint_type: "router" or "node"
# ---------------------------------------------------------------------------

CHECKS = {
    "bgp_summary":        ("BGP Summary",             "router_get",  "/api/v1/router/{r}/bgp?command=summary"),
    "ospf_neighbors":     ("OSPF Neighbors",           "router_get",  "/api/v1/router/{r}/ospf?command=neighbor"),
    "network_interfaces": ("Network Interfaces",       "node_get",    "/api/v1/router/{r}/node/{n}/networkInterface"),
    "device_interfaces":  ("Device Interfaces",        "node_get",    "/api/v1/router/{r}/node/{n}/deviceInterface"),
    "peer_detail":        ("Peer / Adjacency Detail",  "node_get",    "/api/v1/router/{r}/node/{n}/adjacency"),
    "node_status":        ("Node Status",              "node_get",    "/api/v1/router/{r}/node/{n}/status"),
    "node_version":       ("Node Version",             "node_get",    "/api/v1/router/{r}/node/{n}/version"),
    "aggregate_sessions": ("Aggregate Sessions",       "router_post", "/api/v1/router/{r}/stats/aggregate-session/node/session-count"),
    "active_alarms":      ("Active Alarms",            "router_get",  "/api/v1/router/{r}/alarm"),

}


# ---------------------------------------------------------------------------
# API layer
# ---------------------------------------------------------------------------

def authenticate(base_url, username, password, verify):
    r = requests.post(
        f"{base_url}/api/v1/login",
        json={"username": username, "password": password},
        verify=verify, timeout=60,
    )
    if r.status_code == 200:
        token = r.json().get("token") or r.json().get("sessionToken")
        if token:
            return token
    raise Exception(f"Login failed ({r.status_code}): {r.text[:300]}")


def rest_get(token, base_url, endpoint, verify=False):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{base_url}{endpoint}", headers=headers, verify=verify, timeout=30)
    r.raise_for_status()
    return r.json()


def rest_post(token, base_url, endpoint, verify=False):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(f"{base_url}{endpoint}", headers=headers, verify=verify, timeout=30)
    r.raise_for_status()
    return r.json()



def collect_check(token, base_url, router, nodes, cmd_key, verify=False):
    """Collect one check for one router; return deserialisable data."""
    label, etype, tpl = CHECKS[cmd_key]
    if etype == "router_get":
        return rest_get(token, base_url, tpl.format(r=router), verify=verify)
    elif etype == "router_post":
        return rest_post(token, base_url, tpl.format(r=router), verify=verify)
    elif etype == "node_get":
        return {n: rest_get(token, base_url, tpl.format(r=router, n=n), verify=verify)
                for n in nodes}
    raise ValueError(f"Unknown endpoint type: {etype}")


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def flatten(obj, prefix="", sep="."):
    """Recursively flatten dict/list → {dotted.key: str_value}."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{sep}{k}" if prefix else str(k), sep))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]", sep))
    else:
        out[prefix] = str(obj) if obj is not None else ""
    return out


def compute_changes(pre, post, cmd_key):
    pf = flatten(pre)
    qf = flatten(post)
    rows = []
    for k in sorted(set(pf) | set(qf)):
        v1, v2 = pf.get(k), qf.get(k)
        if v1 != v2:
            rows.append({
                "command": cmd_key,
                "path":    k,
                "pre":     v1 if v1 is not None else "",
                "post":    v2 if v2 is not None else "",
                "change":  "Added" if v1 is None else "Removed" if v2 is None else "Changed",
            })
    return rows


def char_diff(a, b):
    """Return (pre_segments, post_segments) — each is [(text, is_highlighted)]."""
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    pre, post = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            pre.append((a[i1:i2], False))
            post.append((b[j1:j2], False))
        elif tag == "delete":
            pre.append((a[i1:i2], True))
        elif tag == "insert":
            post.append((b[j1:j2], True))
        elif tag == "replace":
            pre.append((a[i1:i2], True))
            post.append((b[j1:j2], True))
    return pre, post


# ---------------------------------------------------------------------------
# Worker — runs in background thread, communicates via queue
# ---------------------------------------------------------------------------

def worker(q, cancel, token, base_url, router_nodes, selected_routers,
           enabled_checks, suffix, workdir, verify=False):
    """
    Background worker for collecting checks and computing diffs.
    Posts messages to q:
      ("progress", router, check_key, "ok"|"err", detail_str)
      ("done", diff_data_or_None)
      ("error", traceback_str)
    """
    try:
        ts = datetime.now().strftime("%Y%m%d-%H%M")
        total = len(selected_routers) * len(enabled_checks)
        done  = 0

        for router in selected_routers:
            if cancel.is_set():
                break
            nodes = router_nodes.get(router, [])
            for key in enabled_checks:
                if cancel.is_set():
                    break
                label = CHECKS[key][0]
                try:
                    data = collect_check(token, base_url, router, nodes, key, verify=verify)
                    path = os.path.join(workdir, f"{router}-{suffix}-{key}-{ts}.json")
                    with open(path, "w") as f:
                        json.dump(data, f, indent=2)
                    q.put(("progress", router, label, "ok", path))
                except Exception as e:
                    q.put(("progress", router, label, "err", f"{type(e).__name__}: {e}"))
                done += 1
                q.put(("tick", done, total))

        if suffix == "post" and not cancel.is_set():
            diff_data = {}
            for router in selected_routers:
                diff_data[router] = {}
                for key in enabled_checks:
                    pre_files = sorted(
                        f for f in os.listdir(workdir)
                        if f.startswith(f"{router}-pre-{key}-") and f.endswith(".json")
                    )
                    post_path = os.path.join(workdir, f"{router}-post-{key}-{ts}.json")
                    if not pre_files or not os.path.exists(post_path):
                        continue
                    pre_path = os.path.join(workdir, pre_files[-1])
                    try:
                        with open(pre_path)  as f: pre  = json.load(f)
                        with open(post_path) as f: post = json.load(f)
                        diff_data[router][key] = compute_changes(pre, post, key)
                    except Exception as e:
                        q.put(("progress", router, f"diff/{key}", "err", str(e)))
            q.put(("done", diff_data))
        else:
            q.put(("done", None))

    except Exception:
        import traceback
        q.put(("error", traceback.format_exc()))


# ---------------------------------------------------------------------------
# Detail dialog — side-by-side char-level diff
# ---------------------------------------------------------------------------

class DetailDialog(tk.Toplevel):
    def __init__(self, parent, change, debug=False):
        super().__init__(parent)
        self.title("Change Detail")
        self.geometry("860x420")
        self.resizable(True, True)
        self.configure(bg=BG)
        self._build(change)

    def _build(self, c):
        meta = ttk.Frame(self, padding=(10, 8, 10, 4))
        meta.pack(fill="x")
        label = CHECKS.get(c["command"], (c["command"],))[0]
        badge_fg = {"Added": GREEN, "Removed": RED, "Changed": YELLOW}.get(c["change"], FG)

        ttk.Label(meta, text=label, foreground=ACCENT,
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(meta, text="  ›  ", foreground=GRAY).pack(side="left")
        ttk.Label(meta, text=c["path"], foreground=FG).pack(side="left")
        ttk.Label(meta, text=f"  [{c['change']}]", foreground=badge_fg).pack(side="left")

        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=10, pady=4)

        pre_lf  = ttk.LabelFrame(pane, text="Pre",  padding=4)
        post_lf = ttk.LabelFrame(pane, text="Post", padding=4)
        pane.add(pre_lf,  weight=1)
        pane.add(post_lf, weight=1)

        def make_text(parent):
            t = tk.Text(parent, wrap="word", bg=BG2, fg=FG, insertbackground=FG,
                        font=("Consolas", 10), relief="flat", state="normal", padx=4, pady=4)
            sb = ttk.Scrollbar(parent, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            t.pack(fill="both", expand=True)
            return t

        pre_t  = make_text(pre_lf)
        post_t = make_text(post_lf)

        pre_t .tag_configure("hl", background="#5a2828", foreground="#ffaaaa")
        post_t.tag_configure("hl", background="#1e4a1e", foreground="#aaffaa")

        pre_segs, post_segs = char_diff(c["pre"], c["post"])
        for seg, hi in pre_segs:
            pre_t.insert("end", seg, "hl" if hi else "")
        for seg, hi in post_segs:
            post_t.insert("end", seg, "hl" if hi else "")

        pre_t .configure(state="disabled")
        post_t.configure(state="disabled")

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 8))


# ---------------------------------------------------------------------------
# Per-router diff tab
# ---------------------------------------------------------------------------

class RouterTab(ttk.Frame):
    def __init__(self, parent, rows, debug=False):
        super().__init__(parent)
        self._all   = rows
        self._debug = debug
        self._build()

    def _build(self):
        # Filter / toolbar row
        fb = ttk.Frame(self, padding=(4, 4))
        fb.pack(fill="x")
        ttk.Label(fb, text="Filter:").pack(side="left", padx=(0, 4))
        self._filter = tk.StringVar()
        self._filter.trace_add("write", self._refresh)
        ttk.Entry(fb, textvariable=self._filter, width=26).pack(side="left", padx=4)
        ttk.Label(fb, text="Show:").pack(side="left", padx=(10, 4))
        self._show = tk.StringVar(value="All")
        cb = ttk.Combobox(fb, textvariable=self._show,
                          values=["All", "Added", "Removed", "Changed"],
                          state="readonly", width=10)
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", self._refresh)

        # Treeview
        tf = ttk.Frame(self)
        tf.pack(fill="both", expand=True)

        cols = ("check", "path", "pre", "post", "change")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        hdrs   = {"check": "Check", "path": "Path", "pre": "Pre Value",
                  "post": "Post Value", "change": "Change"}
        widths = {"check": 160, "path": 230, "pre": 240, "post": 240, "change": 85}
        for col in cols:
            self._tree.heading(col, text=hdrs[col],
                               command=lambda c=col: self._sort(c))
            self._tree.column(col, width=widths[col], minwidth=70,
                              anchor="center" if col == "change" else "w",
                              stretch=(col == "path"))

        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal",  command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)

        self._tree.tag_configure("Added",   background="#1a3a1a", foreground=GREEN)
        self._tree.tag_configure("Removed", background="#3a1a1a", foreground=RED)
        self._tree.tag_configure("Changed", background="#2e2800", foreground=YELLOW)
        self._tree.bind("<Double-1>", self._on_double_click)

        self._count_lbl = ttk.Label(self, foreground=GRAY, anchor="e")
        self._count_lbl.pack(fill="x", padx=6, pady=2)

        self._sort_col = None
        self._sort_rev = False
        self._refresh()

    def _visible(self):
        text = self._filter.get().lower()
        show = self._show.get()
        def match(r):
            if show != "All" and r["change"] != show:
                return False
            if text:
                lbl = CHECKS.get(r["command"], (r["command"],))[0].lower()
                return (text in r["path"].lower() or text in r["pre"].lower()
                        or text in r["post"].lower() or text in lbl)
            return True
        rows = [r for r in self._all if match(r)]
        if self._sort_col:
            rows = sorted(rows, key=lambda r: r.get(self._sort_col, ""),
                          reverse=self._sort_rev)
        return rows

    def _refresh(self, *_):
        rows = self._visible()
        self._tree.delete(*self._tree.get_children())
        for r in rows:
            lbl = CHECKS.get(r["command"], (r["command"],))[0]
            pre_s  = r["pre"] [:120] + ("…" if len(r["pre"])  > 120 else "")
            post_s = r["post"][:120] + ("…" if len(r["post"]) > 120 else "")
            self._tree.insert("", "end",
                              values=(lbl, r["path"], pre_s, post_s, r["change"]),
                              tags=(r["change"],))
        self._count_lbl.config(text=f"{len(rows)} of {len(self._all)} change(s)")

    def _sort(self, col):
        key_map = {"check": "command", "path": "path", "pre": "pre",
                   "post": "post", "change": "change"}
        k = key_map.get(col, col)
        if self._sort_col == k:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = k
            self._sort_rev = False
        self._refresh()

    def _on_double_click(self, _event):
        iid = self._tree.focus()
        if not iid:
            return
        vals = self._tree.item(iid, "values")  # (check_label, path, pre_short, post_short, change)
        # Resolve to full original record using label + path
        match = next(
            (r for r in self._visible()
             if CHECKS.get(r["command"], (r["command"],))[0] == vals[0]
             and r["path"] == vals[1]),
            None,
        )
        if match:
            DetailDialog(self, match)


# ---------------------------------------------------------------------------
# Diff viewer window
# ---------------------------------------------------------------------------

class DiffViewer(tk.Toplevel):
    def __init__(self, parent, diff_data, debug=False):
        super().__init__(parent)
        self.title("Pre / Post Diff Results")
        self.geometry("1220x740")
        self.minsize(900, 500)
        self.configure(bg=BG2)
        self._diff_data = diff_data
        self._debug     = debug
        self._build()

    def _build(self):
        dd = self._diff_data
        all_rows = [c for d in dd.values() for ch in d.values() for c in ch]
        added   = sum(1 for c in all_rows if c["change"] == "Added")
        removed = sum(1 for c in all_rows if c["change"] == "Removed")
        changed = sum(1 for c in all_rows if c["change"] == "Changed")

        # Summary bar
        hdr = ttk.Frame(self, padding=(12, 8))
        hdr.pack(fill="x")
        ttk.Label(hdr, text=f"Total changes: {len(all_rows)}",
                  font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 18))
        ttk.Label(hdr, text=f"▲ Added: {added}",     foreground=GREEN ).pack(side="left", padx=8)
        ttk.Label(hdr, text=f"▼ Removed: {removed}", foreground=RED   ).pack(side="left", padx=8)
        ttk.Label(hdr, text=f"↔ Changed: {changed}", foreground=YELLOW).pack(side="left", padx=8)
        ttk.Button(hdr, text="Export CSV",
                   command=self._export_csv).pack(side="right", padx=4)
        ttk.Separator(self).pack(fill="x", padx=8)

        if not all_rows:
            ttk.Label(self, text="No differences found between pre and post checks.",
                      foreground=GREEN, font=("Segoe UI", 12)).pack(expand=True)
            return

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        for router in sorted(dd):
            rows = [c for ch in dd[router].values() for c in ch]
            if not rows:
                continue
            tab = RouterTab(nb, rows, debug=self._debug)
            nb.add(tab, text=f"{router}  ({len(rows)})")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save diff as CSV",
            parent=self,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Router", "Check", "Path", "Pre Value", "Post Value", "Change"])
                for router, cmd_dict in sorted(self._diff_data.items()):
                    for cmd_key, rows in cmd_dict.items():
                        lbl = CHECKS.get(cmd_key, (cmd_key,))[0]
                        for c in rows:
                            w.writerow([router, lbl, c["path"], c["pre"], c["post"], c["change"]])
            messagebox.showinfo("Exported", f"Saved to:\n{path}", parent=self)
        except Exception as e:
            messagebox.showerror("Export Error", str(e), parent=self)


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, debug=False):
        super().__init__()
        self.title("SSR Pre/Post Check Tool")
        self.geometry("1020x740")
        self.minsize(820, 580)
        self.configure(bg=BG2)

        self._debug       = debug
        self.token        = None
        self.base_url     = None
        self.router_nodes = {}      # {router: [node, ...]}
        self.router_vars  = {}      # {router: BooleanVar}
        self.workdir      = os.getcwd()
        self._diff_data   = None
        self._cancel      = threading.Event()
        self._verify      = False   # TLS verify param; False or path to CA bundle

        self._apply_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Style
    # ------------------------------------------------------------------

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",
                    background=BG, foreground=FG, fieldbackground=ENTRY,
                    troughcolor=BG2, bordercolor=GRAY, darkcolor=BG2, lightcolor=BG,
                    relief="flat", focuscolor=ACCENT)
        s.configure("TFrame",    background=BG)
        s.configure("TLabel",    background=BG, foreground=FG)
        s.configure("TButton",   background=BTN, foreground=FG, padding=6, relief="flat")
        s.map("TButton",
              background=[("active", ACCENT),   ("disabled", GRAY)],
              foreground=[("active", BG2),       ("disabled", "#555")])
        s.configure("Accent.TButton", background=ACCENT, foreground=BG2, padding=6)
        s.map("Accent.TButton",
              background=[("active", "#74c7ec"), ("disabled", GRAY)],
              foreground=[("active", BG2),       ("disabled", "#555")])
        s.configure("Danger.TButton", background="#f38ba8", foreground=BG2, padding=6)
        s.map("Danger.TButton",
              background=[("active", "#ff7f9f"), ("disabled", GRAY)],
              foreground=[("active", BG2)])
        s.configure("TEntry",    fieldbackground=ENTRY, foreground=FG, insertcolor=FG)
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.map("TCheckbutton",    background=[("active", BG)])
        s.configure("TNotebook", background=BG2, bordercolor=GRAY, tabmargins=[2, 2, 2, 0])
        s.configure("TNotebook.Tab", background=BTN, foreground=FG, padding=(12, 4))
        s.map("TNotebook.Tab",
              background=[("selected", BG),    ("active", ACCENT)],
              foreground=[("selected", ACCENT), ("active", BG2)])
        s.configure("Treeview",
                    background=ENTRY, foreground=FG, fieldbackground=ENTRY, rowheight=24)
        s.configure("Treeview.Heading",
                    background=BTN, foreground=ACCENT, relief="flat", padding=4)
        s.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", BG2)])
        s.configure("TScrollbar",  background=BTN, troughcolor=BG2, arrowcolor=FG, relief="flat")
        s.configure("TLabelframe", background=BG, bordercolor=GRAY)
        s.configure("TLabelframe.Label", background=BG, foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        s.configure("TProgressbar", background=ACCENT, troughcolor=BG2)
        s.configure("TCombobox",   fieldbackground=ENTRY, foreground=FG, background=BTN)
        s.map("TCombobox",
              fieldbackground=[("readonly", ENTRY)],
              foreground=[("readonly", FG)])
        s.configure("TSeparator", background=GRAY)
        self.option_add("*TCombobox*Listbox.background", ENTRY)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ── Connection bar ─────────────────────────────────────────────
        conn = ttk.Frame(self, padding=(10, 8, 10, 6))
        conn.pack(fill="x")

        ttk.Label(conn, text="Conductor URL:").pack(side="left", padx=(0, 4))
        self._url  = tk.StringVar(value="https://")
        ttk.Entry(conn, textvariable=self._url, width=30).pack(side="left", padx=2)

        ttk.Label(conn, text="User:").pack(side="left", padx=(8, 4))
        self._user = tk.StringVar()
        ttk.Entry(conn, textvariable=self._user, width=12).pack(side="left", padx=2)

        ttk.Label(conn, text="Password:").pack(side="left", padx=(8, 4))
        self._pass = tk.StringVar()
        ttk.Entry(conn, textvariable=self._pass, show="●", width=12).pack(side="left", padx=2)

        self._conn_btn = ttk.Button(conn, text="Connect",
                                    style="Accent.TButton",
                                    command=self._connect_async)
        self._conn_btn.pack(side="left", padx=(10, 4))

        ttk.Button(conn, text="📁 Workdir",
                   command=self._pick_workdir).pack(side="left", padx=4)

        self._workdir_lbl = ttk.Label(conn, text=self.workdir, foreground=GRAY)
        self._workdir_lbl.pack(side="left", padx=6)

        # ── SSL verification row ───────────────────────────────────────
        ssl_row = ttk.Frame(self, padding=(10, 2, 10, 4))
        ssl_row.pack(fill="x")

        self._ssl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ssl_row, text="Verify SSL",
                        variable=self._ssl_var,
                        command=self._toggle_ssl).pack(side="left", padx=(0, 8))

        ttk.Label(ssl_row, text="CA Bundle (optional):").pack(side="left", padx=(0, 4))
        self._cert_var = tk.StringVar()
        self._cert_entry = ttk.Entry(ssl_row, textvariable=self._cert_var,
                                     width=38, state="disabled")
        self._cert_entry.pack(side="left", padx=2)
        self._cert_browse = ttk.Button(ssl_row, text="Browse…",
                                       command=self._browse_cert, state="disabled")
        self._cert_browse.pack(side="left", padx=4)

        self._ssl_warn = ttk.Label(
            ssl_row,
            text="⚠  Certificate verification is OFF — credentials sent without TLS validation",
            foreground=YELLOW,
        )
        self._ssl_warn.pack(side="left", padx=8)

        ttk.Separator(self).pack(fill="x", padx=6)

        # ── Main paned area ────────────────────────────────────────────
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=8, pady=6)

        # Left panel: router list ──────────────────────────────────────
        left = ttk.LabelFrame(pane, text="Routers", padding=6)
        pane.add(left, weight=1)

        sel_row = ttk.Frame(left)
        sel_row.pack(fill="x", pady=(0, 4))
        ttk.Button(sel_row, text="All",  command=self._sel_all ).pack(side="left", padx=2)
        ttk.Button(sel_row, text="None", command=self._sel_none).pack(side="left", padx=2)
        self._sel_count = ttk.Label(sel_row, text="0 selected", foreground=GRAY)
        self._sel_count.pack(side="right")

        wrap = ttk.Frame(left)
        wrap.pack(fill="both", expand=True)
        self._router_canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0, width=210)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self._router_canvas.yview)
        self._router_canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._router_canvas.pack(side="left", fill="both", expand=True)
        self._router_inner = ttk.Frame(self._router_canvas)
        self._cwin = self._router_canvas.create_window((0, 0), window=self._router_inner, anchor="nw")
        self._router_inner.bind("<Configure>",
            lambda e: self._router_canvas.configure(
                scrollregion=self._router_canvas.bbox("all")))
        self._router_canvas.bind("<Configure>",
            lambda e: self._router_canvas.itemconfig(self._cwin, width=e.width))
        self._router_canvas.bind("<MouseWheel>",
            lambda e: self._router_canvas.yview_scroll(int(-1 * e.delta / 120), "units"))

        # Right panel: checks + actions + log ─────────────────────────
        right = ttk.Frame(pane, padding=(4, 0))
        pane.add(right, weight=3)

        checks_lf = ttk.LabelFrame(right, text="Checks to Run", padding=(8, 6))
        checks_lf.pack(fill="x", pady=(0, 6))
        self._check_vars = {}
        items = list(CHECKS.items())
        for i, (key, (label, *_)) in enumerate(items):
            v = tk.BooleanVar(value=True)
            self._check_vars[key] = v
            ttk.Checkbutton(checks_lf, text=label, variable=v).grid(
                row=i // 2, column=i % 2, sticky="w", padx=10, pady=2)

        act = ttk.Frame(right)
        act.pack(fill="x", pady=(0, 6))
        self._pre_btn  = ttk.Button(act, text="▶  Run Pre-Check",
                                    style="Accent.TButton",
                                    command=lambda: self._run_async("pre"),
                                    state="disabled")
        self._post_btn = ttk.Button(act, text="▶  Run Post-Check",
                                    command=lambda: self._run_async("post"),
                                    state="disabled")
        self._diff_btn = ttk.Button(act, text="🔍  View Diff",
                                    command=self._open_diff,
                                    state="disabled")
        self._cancel_btn = ttk.Button(act, text="⏹  Cancel",
                                      style="Danger.TButton",
                                      command=self._request_cancel,
                                      state="disabled")
        self._pre_btn   .pack(side="left", padx=(0, 6))
        self._post_btn  .pack(side="left", padx=(0, 6))
        self._diff_btn  .pack(side="left", padx=(0, 10))
        self._cancel_btn.pack(side="left")
        self._progress = ttk.Progressbar(act, mode="determinate", length=140, maximum=100)
        self._progress.pack(side="right")

        log_lf = ttk.LabelFrame(right, text="Log", padding=4)
        log_lf.pack(fill="both", expand=True)
        self._log_w = scrolledtext.ScrolledText(
            log_lf, height=12, state="disabled",
            bg=BG2, fg=FG, insertbackground=FG,
            font=("Consolas", 9), relief="flat", wrap="word",
        )
        self._log_w.pack(fill="both", expand=True)
        self._log_w.tag_configure("ok",   foreground=GREEN)
        self._log_w.tag_configure("err",  foreground=RED)
        self._log_w.tag_configure("info", foreground=ACCENT)
        self._log_w.tag_configure("warn", foreground=YELLOW)
        self._log_w.tag_configure("dbg",  foreground=GRAY)

        # Status bar
        self._status_var = tk.StringVar(value="Not connected.")
        ttk.Label(self, textvariable=self._status_var, foreground=GRAY,
                  anchor="w").pack(fill="x", padx=10, pady=(0, 4))

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _log(self, msg, tag=""):
        self._log_w.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_w.insert("end", f"[{ts}] {msg}\n", tag)
        self._log_w.see("end")
        self._log_w.configure(state="disabled")

    def _status(self, msg):
        self._status_var.set(msg)

    def _set_progress(self, value):
        self._progress["value"] = max(0, min(100, value))

    def _on_close(self):
        """Clear sensitive data before exit."""
        if self.token:
            _secure_erase(self.token)
            self.token = None
        gc.collect()
        self.destroy()

    def _toggle_ssl(self):
        on = self._ssl_var.get()
        state = "normal" if on else "disabled"
        self._cert_entry .configure(state=state)
        self._cert_browse.configure(state=state)
        if on:
            self._ssl_warn.config(
                text="✓  Certificate verification enabled",
                foreground=GREEN,
            )
            self._verify = self._cert_var.get().strip() or True
        else:
            self._ssl_warn.config(
                text="⚠  Certificate verification is OFF — credentials sent without TLS validation",
                foreground=YELLOW,
            )
            self._verify = False

    def _browse_cert(self):
        path = filedialog.askopenfilename(
            title="Select CA certificate bundle",
            filetypes=[("PEM / CRT files", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if path:
            self._cert_var.set(path)
            self._verify = path
            self._ssl_warn.config(
                text=f"✓  Verifying against: {os.path.basename(path)}",
                foreground=GREEN,
            )

    def _pick_workdir(self):
        d = filedialog.askdirectory(title="Working directory for JSON files",
                                    initialdir=self.workdir)
        if d:
            self.workdir = d
            self._workdir_lbl.config(text=d)
            self._log(f"Workdir → {d}", "info")

    def _sel_all(self):
        for v in self.router_vars.values():
            v.set(True)
        self._update_sel_count()

    def _sel_none(self):
        for v in self.router_vars.values():
            v.set(False)
        self._update_sel_count()

    def _update_sel_count(self):
        n = sum(v.get() for v in self.router_vars.values())
        self._sel_count.config(text=f"{n} selected")

    def _lock_actions(self):
        self._pre_btn   .configure(state="disabled")
        self._post_btn  .configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._set_progress(0)

    def _unlock_actions(self):
        self._pre_btn   .configure(state="normal" if self.token else "disabled")
        self._post_btn  .configure(state="normal" if self.token else "disabled")
        self._cancel_btn.configure(state="disabled")

    def _request_cancel(self):
        self._cancel.set()
        self._log("Cancel requested — stopping after current check…", "warn")

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect_async(self):
        self._conn_btn.configure(state="disabled")
        threading.Thread(target=self._connect, daemon=True).start()

    def _connect(self):
        self.after(0, lambda: self._status("Connecting…"))
        pwd = None
        try:
            url  = self._url.get().strip().rstrip("/")
            user = self._user.get().strip()
            pwd  = self._pass.get()
            if not all([url, user, pwd]):
                raise ValueError("URL, username, and password are all required.")

            self.token    = authenticate(url, user, pwd, verify=self._verify)
            self.base_url = url

            # ── Clear password from UI and memory immediately after auth ──
            self.after(0, lambda: self._pass.set(""))
            _secure_erase(pwd)
            pwd = None
            gc.collect()

            self.after(0, lambda: self._log("Authenticated successfully.", "ok"))
            self.after(0, lambda: self._status("Fetching assets…"))

            assets = rest_get(self.token, self.base_url, "/api/v1/asset?verbose=false",
                              verify=self._verify)
            rn = defaultdict(list)
            for a in assets:
                r, n = a.get("routerName"), a.get("nodeName")
                if r and n:
                    rn[r].append(n)
            self.router_nodes = dict(rn)
            self.after(0, self._populate_routers)

        except Exception as e:
            msg = str(e)
            # Erase password on failure too (it was never cleared above)
            if pwd is not None:
                _secure_erase(pwd)
                self.after(0, lambda: self._pass.set(""))
                gc.collect()
            self.after(0, lambda: self._log(f"Connection error: {msg}", "err"))
            self.after(0, lambda: self._status("Connection failed."))
            self.after(0, lambda: self._conn_btn.configure(state="normal"))

    def _populate_routers(self):
        for w in self._router_inner.winfo_children():
            w.destroy()
        self.router_vars.clear()

        for router in sorted(self.router_nodes):
            v = tk.BooleanVar(value=True)
            self.router_vars[router] = v
            n = len(self.router_nodes[router])
            ttk.Checkbutton(
                self._router_inner,
                text=f"{router}  ({n} node{'s' if n != 1 else ''})",
                variable=v,
                command=self._update_sel_count,
            ).pack(anchor="w", padx=4, pady=1)

        self._update_sel_count()
        self._conn_btn .configure(state="normal")
        self._pre_btn  .configure(state="normal")
        self._post_btn .configure(state="normal")
        count = len(self.router_nodes)
        self._log(f"Found {count} router(s).", "ok")
        self._status(f"Connected — {count} router(s)")

    # ------------------------------------------------------------------
    # Check collection
    # ------------------------------------------------------------------

    def _run_async(self, suffix):
        selected = [r for r, v in self.router_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("No Routers", "Select at least one router.", parent=self)
            return
        enabled = [k for k, v in self._check_vars.items() if v.get()]
        if not enabled:
            messagebox.showwarning("No Checks", "Select at least one check to run.", parent=self)
            return

        self._cancel.clear()
        self._lock_actions()
        self._diff_data = None
        self._diff_btn.configure(state="disabled")

        q = queue.Queue()
        threading.Thread(
            target=worker,
            args=(q, self._cancel, self.token, self.base_url,
                  self.router_nodes, selected, enabled, suffix, self.workdir),
            kwargs={"verify": self._verify},
            daemon=True,
        ).start()
        self._log(
            f"{suffix.upper()} check started — {len(selected)} router(s), "
            f"{len(enabled)} check(s)", "info"
        )
        self._poll_queue(q, suffix, len(selected) * len(enabled))

    def _poll_queue(self, q, suffix, total_steps):
        try:
            while True:
                msg = q.get_nowait()
                kind = msg[0]

                if kind == "progress":
                    _, router, label, status, detail = msg
                    tag = "ok" if status == "ok" else "err"
                    sym = "✓" if status == "ok" else "✗"
                    self._log(f"  {sym} {router} / {label}", tag)
                    if self._debug and detail:
                        self._log(f"    → {detail}", "dbg")

                elif kind == "tick":
                    _, done, _ = msg
                    pct = int(done / total_steps * 100) if total_steps else 100
                    self._set_progress(pct)
                    self._status(f"Running… {done}/{total_steps}")

                elif kind == "done":
                    diff_data = msg[1]
                    self._set_progress(100)
                    if suffix == "post" and diff_data is not None:
                        self._diff_data = diff_data
                        total = sum(len(v) for d in diff_data.values() for v in d.values())
                        routers_with = sum(1 for d in diff_data.values() if any(d.values()))
                        if total:
                            self._log(
                                f"Diff complete — {total} change(s) across "
                                f"{routers_with} router(s). Click View Diff.", "warn"
                            )
                            self._diff_btn.configure(state="normal")
                        else:
                            self._log("Diff complete — no differences found.", "ok")
                    self._log(f"{suffix.capitalize()}-check complete.", "ok")
                    self._status(f"{suffix.capitalize()}-check done.")
                    self._unlock_actions()
                    return

                elif kind == "error":
                    self._log(f"Worker error:\n{msg[1]}", "err")
                    self._unlock_actions()
                    return

        except queue.Empty:
            pass

        # Re-schedule poll
        self.after(120, lambda: self._poll_queue(q, suffix, total_steps))

    # ------------------------------------------------------------------
    # Diff viewer
    # ------------------------------------------------------------------

    def _open_diff(self):
        if not self._diff_data:
            messagebox.showinfo("No Data", "Run a post-check first.", parent=self)
            return
        DiffViewer(self, self._diff_data, debug=self._debug)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SSR Pre/Post Check Tool")
    parser.add_argument("--debug", action="store_true",
                        help="Show extra detail in the log pane")
    args = parser.parse_args()

    app = App(debug=args.debug)
    app.mainloop()


if __name__ == "__main__":
    main()
