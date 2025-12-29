#!/usr/bin/env python3
"""
duplicate_finder_auto.py (updated)

- PC / removable drives scanning (fast: size -> sample -> full hash)
- Android scanning via ADB with:
    * automatic adb discovery
    * interactive remote explorer (navigate /sdcard and subfolders)
    * recursive remote listing using find if available, otherwise BFS via ls -la
    * computing file hashes ON DEVICE when possible (sha256sum/toybox/busybox/md5sum)
    * fallback to adb pull if needed
UI: tkinter minimal: Local / Removable / Android, progress, log, and single Cancel button.

Author: updated for Red — copy-paste ready.
"""
import os
import sys
import time
import shutil
import tempfile
import threading
import queue
import subprocess
import hashlib
from pathlib import Path
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# ---------------- CONFIG ----------------
SAMPLE_SIZE = 64 * 1024  # 64 KB sample for sample-hash
READ_CHUNK = 64 * 1024
MAX_WORKERS = min(8, (os.cpu_count() or 2) * 2)
ADB_SEARCH_COMMON = [
    r"C:\platform-tools",
    r"C:\Android\platform-tools",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools"),
    os.path.join(os.environ.get("ProgramFiles", ""), "Android", "platform-tools"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Android", "platform-tools"),
]
# ----------------------------------------

# ---------------- Helpers ----------------
def human_size(n):
    if n < 1024: return f"{n} B"
    for unit in ("KB","MB","GB","TB"):
        n /= 1024.0
        if n < 1024.0:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"

def run_cmd(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return None, "", "not-found"
    except subprocess.TimeoutExpired:
        return 2, "", "timeout"

# ---------------- ADB discovery ----------------
def find_adb(exhaustive=False):
    import shutil
    p = shutil.which("adb")
    if p:
        return p
    for d in ADB_SEARCH_COMMON:
        exe = os.path.join(d, "adb.exe")
        if os.path.exists(exe):
            return exe
    scr = shutil.which("scrcpy")
    if scr:
        cand = os.path.join(os.path.dirname(scr), "adb.exe")
        if os.path.exists(cand):
            return cand
    if exhaustive:
        for root in ["C:\\"] if os.name == "nt" else ["/"]:
            for dirpath, dirnames, filenames in os.walk(root):
                if "adb.exe" in filenames:
                    return os.path.join(dirpath, "adb.exe")
    return None

def adb_list_devices(adb_exe):
    rc, out, err = run_cmd([adb_exe, "devices", "-l"], timeout=5)
    if rc is None:
        return None, "adb-not-found"
    if rc != 0:
        return [], f"{err or out}"
    lines = out.splitlines()
    devices = []
    for line in lines[1:]:
        line = line.strip()
        if not line: continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        details = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append((serial, state, details))
    return devices, None

def adb_shell(adb_exe, serial, shell_cmd, timeout=30):
    cmd = [adb_exe, "-s", serial, "shell", shell_cmd]
    return run_cmd(cmd, timeout=timeout)

# ---------------- Remote listing helpers (recursive) ----------------
def shell_quote(s):
    # quote for POSIX shell
    if "'" not in s:
        return "'" + s + "'"
    return "'" + s.replace("'", "'\"'\"'") + "'"

def remote_supports_find(adb_exe, serial):
    # try common find variants: find -type f -printf, toybox find
    checks = [
        "find --version",
        "toybox find --version",
        "busybox find --help",
    ]
    for c in checks:
        rc, out, err = adb_shell(adb_exe, serial, c, timeout=5)
        if rc == 0:
            return True
    return False

def adb_remote_list_by_find(adb_exe, serial, remote_root):
    # fast attempt: find <root> -type f -printf "%s\t%p\0"
    # not all finds support -printf; try toybox/busybox/gnu find heuristics
    cmd = f"find {shell_quote(remote_root)} -type f -printf '%s\\t%p\\0'"
    rc, out, err = adb_shell(adb_exe, serial, cmd, timeout=120)
    if rc == 0 and out:
        res = []
        parts = out.split("\0")
        for p in parts:
            if not p: continue
            try:
                sz_s, path = p.split("\t", 1)
                res.append((int(sz_s), path))
            except Exception:
                continue
        if res:
            return res, None
    # try toybox find with -printf maybe missing; fallback false
    return None, "find-printf-not-supported"

def adb_remote_list_bfs(adb_exe, serial, remote_root, cancel_event=None, progress_callback=None):
    """
    BFS directory walker using 'ls -la' per directory, returns list of (size, path).
    This is slower than find but robust across devices.
    progress_callback(curr_count) is optional to update UI.
    """
    res = []
    q = deque()
    q.append(remote_root.rstrip("/"))
    processed = 0
    while q:
        if cancel_event and cancel_event.is_set():
            return None, "cancelled"
        curr = q.popleft()
        # list directory with ls -la - use LC_ALL=C for consistent format
        rc, out, err = adb_shell(adb_exe, serial, f"ls -la {shell_quote(curr)}", timeout=30)
        if rc != 0:
            # try plain ls if -la fails
            rc2, out2, err2 = adb_shell(adb_exe, serial, f"ls {shell_quote(curr)}", timeout=30)
            out = out2 if rc2 == 0 else out
        if not out:
            continue
        lines = out.splitlines()
        # parse ls -la lines. Format varies: we search for lines that look like files
        for line in lines:
            line = line.strip()
            if not line or line.startswith("total"):
                continue
            # directory heading (rare) or file entry. We'll try heuristic: lines that start with d are dirs
            parts = line.split()
            if len(parts) >= 6 and parts[0][0] == "d":
                # directory entry: last token is name
                name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
                # ignore '.' and '..'
                if name in (".", ".."):
                    continue
                # build full path
                child = curr + "/" + name if curr != "/" else "/" + name
                q.append(child)
            elif len(parts) >= 6:
                # file entry: try to find size token (first numeric token)
                size_val = None
                for tok in parts:
                    if tok.isdigit():
                        size_val = int(tok)
                if size_val is None:
                    # fallback: attempt to stat this entry
                    name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
                    child = curr + "/" + name if curr != "/" else "/" + name
                    # try stat -c %s
                    rc3, out3, err3 = adb_shell(adb_exe, serial, f"stat -c %s {shell_quote(child)}", timeout=10)
                    if rc3 == 0 and out3.strip().isdigit():
                        size_val = int(out3.strip())
                else:
                    name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
                    child = curr + "/" + name if curr != "/" else "/" + name
                if size_val is not None:
                    res.append((size_val, child))
            else:
                # can't parse; try treat as name-only line: assume file
                name = line
                child = curr + "/" + name if curr != "/" else "/" + name
                rc4, out4, err4 = adb_shell(adb_exe, serial, f"stat -c %s {shell_quote(child)}", timeout=10)
                if rc4 == 0 and out4.strip().isdigit():
                    res.append((int(out4.strip()), child))
        processed += 1
        if progress_callback and processed % 20 == 0:
            progress_callback(processed)
    return res, None

# ---------------- Remote hash (on-device) ----------------
def detect_remote_hash_tool(adb_exe, serial):
    # prefer sha256sum variants; test common commands
    candidates = [
        ("sha256sum", "sha256sum --version"),
        ("toybox sha256sum", "toybox sha256sum --version"),
        ("busybox sha256sum", "busybox sha256sum --help"),
        ("sha1sum", "sha1sum --version"),
        ("md5sum", "md5sum --version")
    ]
    for tool, test in candidates:
        rc, out, err = adb_shell(adb_exe, serial, test, timeout=5)
        if rc == 0:
            return tool.split()[0] if " " not in tool else tool
    return None

def adb_remote_hash(adb_exe, serial, remote_path):
    # try several tools in order; return hash or error token
    tools = ["sha256sum", "toybox sha256sum", "busybox sha256sum", "sha1sum", "md5sum"]
    rpath = shell_quote(remote_path)
    for t in tools:
        rc, out, err = adb_shell(adb_exe, serial, f"{t} {rpath}", timeout=60)
        if rc == 0 and out:
            first = out.splitlines()[0].strip()
            token = first.split()[0]
            if all(c in "0123456789abcdefABCDEF" for c in token):
                return token
    return f"ERR_REMOTE_HASH"

# ---------------- Local hash helpers ----------------
def sample_hash_local(path: Path, sample_size=SAMPLE_SIZE):
    try:
        sz = path.stat().st_size
        if sz == 0:
            return "EMPTYFILE"
        if sz < sample_size * 2:
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            h.update(f.read(sample_size))
            f.seek(max(0, sz - sample_size))
            h.update(f.read(sample_size))
        return h.hexdigest()
    except Exception as e:
        return f"ERR_SAMPLE:{e}"

def full_hash_local(path: Path, chunk=READ_CHUNK):
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for cb in iter(lambda: f.read(chunk), b""):
                h.update(cb)
        return h.hexdigest()
    except Exception as e:
        return f"ERR_FULL:{e}"

# ---------------- GUI + Main App ----------------
class DuplicateFinderAuto:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Duplicate Finder — Auto (Android recursive)")
        self.queue = queue.Queue()
        self.cancel_flag = threading.Event()
        self.worker = None
        self.adb_exe = find_adb(exhaustive=False)
        self._build_ui()
        self.root.after(100, self._process_queue)

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(sticky="nsew")
        ttk.Label(frm, text="Source: Local folder | Removable drive | Android (ADB)").grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(frm, mode="determinate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=6)
        self.current = ttk.Label(frm, text="")
        self.current.grid(row=2, column=0, sticky="w")
        btns = ttk.Frame(frm); btns.grid(row=3, column=0, sticky="ew", pady=6)
        ttk.Button(btns, text="Local folder...", command=self.action_local).pack(side="left", padx=4)
        ttk.Button(btns, text="Removable drive...", command=self.action_removable).pack(side="left", padx=4)
        ttk.Button(btns, text="Android via ADB...", command=self.action_android).pack(side="left", padx=4)
        self.cancel_btn = ttk.Button(btns, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=8)
        ttk.Button(btns, text="Quit", command=self.root.destroy).pack(side="right", padx=4)
        self.txt = tk.Text(frm, height=18, wrap="word")
        self.txt.grid(row=4, column=0, sticky="nsew")
        self.txt.insert("end", "Ready.\n")
        self.txt.config(state="disabled")
        self.root.rowconfigure(0, weight=1); self.root.columnconfigure(0, weight=1)
        frm.rowconfigure(4, weight=1); frm.columnconfigure(0, weight=1)

    # UI helper queue
    def log(self, s):
        self.queue.put(("log", s))
    def set_current(self, s):
        self.queue.put(("cur", s))
    def set_progress(self, v, m=None):
        self.queue.put(("prog", (v,m)))
    def _process_queue(self):
        try:
            while True:
                typ, payload = self.queue.get_nowait()
                if typ == "log":
                    self.txt.config(state="normal"); self.txt.insert("end", payload + "\n"); self.txt.see("end"); self.txt.config(state="disabled")
                elif typ == "cur":
                    self.current.config(text=payload)
                elif typ == "prog":
                    v,m = payload
                    if m:
                        self.progress.config(maximum=m)
                    self.progress['value'] = v
        except queue.Empty:
            pass
        self.root.after(100, self._process_queue)

    def _cancel(self):
        self.cancel_flag.set()
        self.log("Cancellation requested...")

    # ---- actions ----
    def action_local(self):
        folder = filedialog.askdirectory(title="Select local folder to scan")
        if folder:
            self.start_scan_local(Path(folder))

    def action_removable(self):
        drives = self._detect_removable()
        if not drives:
            messagebox.showinfo("No removable", "No removable drives detected. Insert USB and retry or select local folder.")
            return
        sel = drives[0] if len(drives) == 1 else self._pick_from_list("Choose drive", drives)
        if sel:
            self.start_scan_local(Path(sel))

    def action_android(self):
        # auto-detect adb
        if not self.adb_exe:
            self.log("adb not found in PATH or common folders. Attempting exhaustive search...")
            self.adb_exe = find_adb(exhaustive=True)
            if not self.adb_exe:
                messagebox.showerror("ADB not found", "adb.exe not found. Install platform-tools or add adb to PATH.")
                return
        self.log(f"Using adb: {self.adb_exe}")
        # ensure server
        run_cmd([self.adb_exe, "start-server"], timeout=5)
        devices, err = adb_list_devices(self.adb_exe)
        if devices is None:
            messagebox.showerror("ADB error", f"ADB not usable: {err}")
            return
        if not devices:
            messagebox.showinfo("No device", "No adb devices detected. Enable USB debugging and accept RSA prompt on phone, then retry.")
            return
        # choose device if multiple
        if len(devices) == 1:
            serial, state, details = devices[0]
        else:
            choices = [f"{i+1}. {d[0]} ({d[1]}) {d[2]}" for i,d in enumerate(devices)]
            idx = simpledialog.askinteger("Choose device", "Devices:\n" + "\n".join(choices) + "\nEnter device number:", minvalue=1, maxvalue=len(devices))
            if not idx: return
            serial, state, details = devices[idx-1]
        if state.lower() == "unauthorized":
            messagebox.showwarning("Unauthorized", "Device unauthorized. Accept RSA on phone then retry.")
            return
        # open remote explorer starting at /sdcard
        self._open_remote_explorer(serial, "/sdcard")

    def _detect_removable(self):
        drives = []
        if os.name == "nt":
            import string, ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i, letter in enumerate(string.ascii_uppercase):
                if bitmask & (1 << i):
                    drive = f"{letter}:\\"
                    if drive.upper() == os.path.splitdrive(os.getcwd())[0].upper() + "\\":
                        continue
                    drives.append(drive)
        else:
            path = filedialog.askdirectory(title="Select removable mount")
            if path:
                drives.append(path)
        return [d for d in drives if os.path.exists(d)]

    def _pick_from_list(self, title, items):
        sel = None
        win = tk.Toplevel(self.root)
        win.title(title)
        lb = tk.Listbox(win, width=80, height=10)
        lb.pack(padx=8, pady=8)
        for it in items:
            lb.insert("end", it)
        def on_ok():
            nonlocal sel
            s = lb.curselection()
            if s:
                sel = lb.get(s[0])
            win.destroy()
        def on_cancel():
            win.destroy()
        ttk.Button(win, text="OK", command=on_ok).pack(side="left", padx=8, pady=6)
        ttk.Button(win, text="Cancel", command=on_cancel).pack(side="right", padx=8, pady=6)
        win.transient(self.root); win.grab_set(); self.root.wait_window(win)
        return sel

    # ---- remote explorer (interactive) ----
    def _open_remote_explorer(self, serial, start_path):
        win = tk.Toplevel(self.root)
        win.title(f"Remote explorer: {serial}")
        frame = ttk.Frame(win, padding=8)
        frame.grid(sticky="nsew")
        path_var = tk.StringVar(value=start_path)
        ttk.Label(frame, textvariable=path_var).grid(row=0, column=0, sticky="w")
        lb = tk.Listbox(frame, width=80, height=20)
        lb.grid(row=1, column=0, sticky="nsew", pady=6)
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(btn_frame, text="Up", command=lambda: self._explorer_up(lb, path_var, serial)).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Refresh", command=lambda: self._explorer_refresh(lb, path_var, serial)).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Select this folder", command=lambda: self._explorer_select(win, path_var.get(), serial)).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side="right", padx=4)
        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1)

        # double click to drill into dir or select file
        def on_double(ev):
            sel = lb.curselection()
            if not sel: return
            item = lb.get(sel[0])
            # item format: "<DIR> name" or "size name"
            if item.startswith("<DIR> "):
                newpath = (path_var.get().rstrip("/") + "/" + item[6:]).replace("//","/")
                path_var.set(newpath)
                self._explorer_refresh(lb, path_var, serial)
            else:
                # file double-click => select parent folder and start scan for that file's parent
                file_rel = item.split(" ", 1)[1] if " " in item else item
                selected_folder = path_var.get()
                win.destroy()
                self.start_scan_android((serial, selected_folder))
        lb.bind("<Double-Button-1>", on_double)

        # initial load
        self._explorer_refresh(lb, path_var, serial)
        win.transient(self.root); win.grab_set(); self.root.wait_window(win)

    def _explorer_refresh(self, listbox, path_var, serial):
        listbox.delete(0, "end")
        curr = path_var.get()
        self.log(f"Listing {curr} ...")
        rc, out, err = adb_shell(self.adb_exe, serial, f"ls -la {shell_quote(curr)}", timeout=10)
        if rc != 0:
            # try plain ls non-recursive
            rc2, out2, err2 = adb_shell(self.adb_exe, serial, f"ls {shell_quote(curr)}", timeout=10)
            out = out2 if rc2 == 0 else out
        if not out:
            self.log(f"Empty or inaccessible: {curr}")
            return
        # parse entries
        lines = out.splitlines()
        # skip header lines
        for line in lines:
            line = line.strip()
            if not line or line.startswith("total"):
                continue
            parts = line.split()
            # directory detection via first char 'd' in permissions
            if len(parts) >= 6 and parts[0][0] == "d":
                name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
                listbox.insert("end", "<DIR> " + name)
            else:
                # try to extract size and name
                size_val = None
                # find first numeric token
                for tok in parts:
                    if tok.isdigit():
                        size_val = tok
                        break
                name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
                if size_val:
                    listbox.insert("end", f"{size_val} {name}")
                else:
                    listbox.insert("end", name)

    def _explorer_up(self, listbox, path_var, serial):
        curr = path_var.get().rstrip("/")
        if curr == "" or curr == "/":
            return
        parent = "/" if curr.count("/") <= 1 else curr.rsplit("/",1)[0]
        path_var.set(parent)
        self._explorer_refresh(listbox, path_var, serial)

    def _explorer_select(self, win, path, serial):
        win.destroy()
        self.start_scan_android((serial, path))

    # ---- scanning flows ----
    def start_scan_local(self, folder: Path):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "A scan is already running.")
            return
        self.cancel_flag.clear()
        self.cancel_btn.config(state="normal")
        self.worker = threading.Thread(target=self._scan_local_worker, args=(folder,), daemon=True)
        self.worker.start()

    def start_scan_android(self, target):
        # target is (serial, remote_root)
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "A scan is already running.")
            return
        self.cancel_flag.clear()
        self.cancel_btn.config(state="normal")
        self.worker = threading.Thread(target=self._scan_android_worker, args=(target,), daemon=True)
        self.worker.start()

    # ---- local worker ----
    def _scan_local_worker(self, folder: Path):
        try:
            self.log(f"Indexing local: {folder}")
            all_files = [p for p in folder.rglob("*") if p.is_file()]
            total = len(all_files)
            self.log(f"Found {total} files.")
            if total == 0:
                self.log("No files.")
                return
            # group by size
            size_map = defaultdict(list)
            processed = 0
            self.set_progress(0, total)
            for p in all_files:
                if self.cancel_flag.is_set(): self.log("Cancelled"); return
                try:
                    s = p.stat().st_size
                except Exception:
                    s = -1
                size_map[s].append(p)
                processed += 1
                if processed % 200 == 0:
                    self.set_progress(processed)
                    self.set_current(f"Indexed {processed}/{total}: {p.name}")
            self.set_progress(processed)
            candidates = [f for s, fl in size_map.items() if s >= 0 and len(fl) > 1 for f in fl]
            self.log(f"{len(candidates)} candidate files for sampling.")
            sample_map = defaultdict(list)
            if candidates:
                done = 0; self.set_progress(0, len(candidates))
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exc:
                    futmap = {exc.submit(sample_hash_local, p): p for p in candidates}
                    for fut in as_completed(futmap):
                        if self.cancel_flag.is_set(): self.log("Cancelled during sampling"); return
                        p = futmap[fut]; h = fut.result(); sample_map[(p.stat().st_size, h)].append(p)
                        done += 1
                        if done % 50 == 0 or done == len(candidates):
                            self.set_progress(done); self.set_current(f"Sampling {done}/{len(candidates)}: {p.name}")
            to_full = []
            for (sz, sh), fl in sample_map.items():
                if len(fl) > 1:
                    to_full.extend(fl)
            to_full = list(dict.fromkeys(to_full))
            self.log(f"{len(to_full)} files need full hashing.")
            full_map = defaultdict(list)
            if to_full:
                done = 0; self.set_progress(0, len(to_full))
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exc:
                    futmap = {exc.submit(full_hash_local, p): p for p in to_full}
                    for fut in as_completed(futmap):
                        if self.cancel_flag.is_set(): self.log("Cancelled during hashing"); return
                        p = futmap[fut]; h = fut.result(); full_map[h].append(p)
                        done += 1
                        if done % 50 == 0 or done == len(to_full):
                            self.set_progress(done); self.set_current(f"Hashing {done}/{len(to_full)}: {p.name}")
            dup_groups = [sorted(g, key=lambda x: str(x).lower()) for g in full_map.values() if len(g) > 1]
            if not dup_groups:
                self.log("No duplicates found.")
                return
            self.log(f"Found {len(dup_groups)} duplicate groups.")
            for i, g in enumerate(dup_groups, 1):
                self.log(f"Group {i}:")
                for p in g:
                    try: self.log(f"  {p} ({human_size(p.stat().st_size)})")
                    except: self.log(f"  {p}")
                self.log("")
            choice = messagebox.askyesnocancel("Action", "Delete duplicates (Yes), Move to 'duplicates_review' (No), Cancel?")
            if choice is None:
                self.log("No action.")
                return
            if choice:
                deleted = 0
                for g in dup_groups:
                    for p in g[1:]:
                        try: p.unlink(); deleted += 1; self.log(f"Deleted {p}")
                        except Exception as e: self.log(f"Failed to delete {p}: {e}")
                self.log(f"Deleted {deleted} files.")
            else:
                moved = 0
                for g in dup_groups:
                    keeper = g[0]; dest = keeper.parent / "duplicates_review"; dest.mkdir(parents=True, exist_ok=True)
                    for p in g[1:]:
                        try:
                            tgt = dest / p.name
                            if tgt.exists(): tgt = dest / f"{p.stem}_dup{p.suffix}"
                            shutil.move(str(p), str(tgt)); moved += 1; self.log(f"Moved {p} -> {tgt}")
                        except Exception as e:
                            self.log(f"Failed to move {p}: {e}")
                self.log(f"Moved {moved} files.")
        finally:
            self.set_progress(0,1); self.set_current("Idle"); self.cancel_btn.config(state="disabled")

    # ---- android worker ----
    def _scan_android_worker(self, target):
        try:
            serial, remote_root = target
            adb_exe = self.adb_exe
            self.log(f"Listing remote (recursive) under: {remote_root} ...")
            # prefer find-listing
            files_info, err = adb_remote_list_by_find(adb_exe, serial, remote_root)
            if files_info is None:
                # fall back to BFS walker (robust)
                self.log("Fast find listing unavailable -> using BFS directory walker (robust, may be slower)...")
                files_info, err = adb_remote_list_bfs(adb_exe, serial, remote_root,
                                                     cancel_event=self.cancel_flag,
                                                     progress_callback=lambda n: self.set_current(f"Indexed {n} directories"))
                if files_info is None:
                    self.log(f"Remote listing failed: {err}")
                    return
            total = len(files_info)
            self.log(f"Remote listing completed: {total} files found.")
            if total == 0:
                self.log("No files found.")
                return
            # group by size
            size_map = defaultdict(list)
            processed = 0
            self.set_progress(0, total)
            for sz, path in files_info:
                if self.cancel_flag.is_set(): self.log("Cancelled"); return
                size_map[sz].append(path)
                processed += 1
                if processed % 200 == 0:
                    self.set_progress(processed, total)
                    self.set_current(f"Indexed remote {processed}/{total}: {path}")
            self.set_progress(processed, total)
            # candidates -> same size groups >1
            candidates = []
            for sz, group in size_map.items():
                if sz >= 0 and len(group) > 1:
                    candidates.extend(group)
            self.log(f"{len(candidates)} remote candidate files for hashing.")
            if not candidates:
                self.log("No duplicates by size.")
                return
            # detect remote hash tool
            tool = detect_remote_hash_tool(adb_exe, serial)
            if tool:
                self.log(f"Remote hash tool found: {tool}. Computing remote hashes ON DEVICE (faster).")
                remote_map = defaultdict(list)
                done = 0
                self.set_progress(0, len(candidates))
                # small worker pool to avoid adb overload
                with ThreadPoolExecutor(max_workers=min(4, MAX_WORKERS)) as exc:
                    futmap = {exc.submit(adb_remote_hash, adb_exe, serial, p): p for p in candidates}
                    for fut in as_completed(futmap):
                        if self.cancel_flag.is_set(): self.log("Cancelled"); return
                        p = futmap[fut]
                        h = fut.result()
                        remote_map[h].append(p)
                        done += 1
                        if done % 20 == 0 or done == len(candidates):
                            self.set_progress(done, len(candidates))
                            self.set_current(f"Remote hashing {done}/{len(candidates)}: {p}")
                dup_groups = [sorted(g, key=lambda x: x.lower()) for h, g in remote_map.items() if len(g) > 1 and not str(h).startswith("ERR_")]
                if not dup_groups:
                    self.log("No duplicates found on device.")
                    return
                self.log(f"Found {len(dup_groups)} duplicate groups on device.")
                for i, g in enumerate(dup_groups,1):
                    self.log(f"Group {i}:")
                    for p in g:
                        self.log(f"  {p}")
                    self.log("")
                # action: delete on device via adb rm or create report
                choice = messagebox.askyesno("Action", "Delete duplicates directly on device? (Yes = delete via adb rm; No = create local+device report)")
                if choice:
                    deleted = 0
                    for g in dup_groups:
                        for p in g[1:]:
                            if self.cancel_flag.is_set(): break
                            rc, out, err = run_cmd([adb_exe, "-s", serial, "shell", f"rm {shell_quote(p)}"], timeout=30)
                            if rc == 0:
                                deleted += 1
                                self.log(f"Deleted on device: {p}")
                            else:
                                self.log(f"Failed to delete {p}: {err or out}")
                    self.log(f"Deleted {deleted} files on device.")
                else:
                    rpt_path = Path(tempfile.mkstemp(prefix="dups_report_", suffix=".txt")[1])
                    with rpt_path.open("w", encoding="utf-8") as f:
                        for i,g in enumerate(dup_groups,1):
                            f.write(f"Group {i}:\n")
                            for p in g:
                                f.write(f"  {p}\n")
                            f.write("\n")
                    self.log(f"Report saved locally: {rpt_path}")
                    try:
                        device_dest = f"/sdcard/duplicates_report_{int(time.time())}.txt"
                        rc, out, err = run_cmd([adb_exe, "-s", serial, "push", str(rpt_path), device_dest], timeout=30)
                        if rc == 0:
                            self.log(f"Report also pushed to device: {device_dest}")
                        else:
                            self.log("Failed to push report to device.")
                    except Exception:
                        pass
                return
            else:
                self.log("No hashing tool on device. Asking user about pull fallback.")
                use_pull = messagebox.askyesno("No hash tool", "Device has no hashing tools. Pull remote folder to PC for scanning? (May need free space)")
                if not use_pull:
                    self.log("User declined pull fallback. Aborting.")
                    return
                tempdir = Path(tempfile.mkdtemp(prefix="adb_pull_"))
                self.log(f"Pulling remote folder to {tempdir} ... (may be slow)")
                rc, out, err = run_cmd([adb_exe, "-s", serial, "pull", remote_root, str(tempdir)], timeout=3600)
                if rc != 0:
                    self.log(f"adb pull failed: {err or out}")
                    shutil.rmtree(tempdir, ignore_errors=True)
                    return
                self.log("Pull done. Scanning pulled folder locally.")
                self._scan_local_worker(tempdir)
                try:
                    shutil.rmtree(tempdir)
                    self.log("Cleaned pulled folder.")
                except Exception:
                    pass
                return
        finally:
            self.set_progress(0,1); self.set_current("Idle"); self.cancel_btn.config(state="disabled")

    # run loop
    def run(self):
        self.root.mainloop()

# ---------------- run ----------------
if __name__ == "__main__":
    import queue
    app = DuplicateFinderAuto()
    app.run()
