"""
fim.py - File Integrity Monitor
Author  : D-Sensei
Version : 2.0
License : MIT

Dependencies (stdlib only + watchdog):
    pip install pyfiglet watchdog

Usage:
    python fim.py
    Then type: baseline | scan | live | logs | export | help | exit
"""

import sys
import os
import hashlib
import sqlite3
import json
import argparse
from datetime import datetime
from pathlib import Path


# 
#  ANSI Color Palette  (same as your original)
# 
GREEN  = '\033[1;32m'
WHITE  = '\033[97m'
RED    = '\033[1;31m'
RESET  = '\033[0m'
GRAY   = '\033[90m'
YELLOW = '\033[1;33m'
CYAN   = '\033[96m'
BLUE   = '\033[1;34m'
BOLD   = '\033[1m'
MAGENTA= '\033[1;35m'

# //////////////////
#  pyfiglet guard
# //////////////////
try:
    import pyfiglet
except ImportError:
    print("[!] Error: 'pyfiglet' module not found.")
    print("[*] Please install it using: pip install pyfiglet")
    sys.exit(1)

# 
#  watchdog guard -> live mode
# 
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# 
#  Global Config
# 
DB_PATH          = "fim_database.db"
LOG_FILE         = "fim_events.log"

# Default directories/extensions to ignore during scans
DEFAULT_IGNORES  = {
    ".git", "__pycache__", ".svn", ".hg",
    "node_modules", ".DS_Store", "Thumbs.db",
    ".idea", ".vscode",
}

SUPPORTED_ALGOS  = ("sha256", "sha1", "md5")


# 
# —> BANNER & CLI SHELL
# 

def generate_banner():
    tool_name      = "fim"
    developer      = "Developed by D-Sensei"
    terminal_width = 80

    try:
        ascii_main = pyfiglet.figlet_format(tool_name, font='slant', width=terminal_width)
        ascii_dev  = pyfiglet.figlet_format(developer, font='digital', width=terminal_width)
    except Exception:
        ascii_main = pyfiglet.figlet_format(tool_name)
        ascii_dev  = f"            {developer}"

    print(f"\n{RED}{BOLD}" + "=" * 60)
    for line in ascii_main.splitlines():
        if line.strip():
            print(f"{RED}{BOLD}{line.center(60)}{RESET}")

    print(f"{GRAY}" + "-" * 60 + RESET)

    for line in ascii_dev.splitlines():
        if line.strip():
            print(f"{WHITE}{line.center(60)}{RESET}")

    print(f"{RED}{BOLD}" + "=" * 60 + RESET + "\n")
    print(f"{CYAN}[+] {WHITE}File Integrity Monitor v2.0 Loaded.{RESET}")
    print(f"{CYAN}[+] {WHITE}Type 'help' to see available commands.{RESET}\n")


def show_help():
    """Print the command reference table."""
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{WHITE}  FIM Command Reference{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")
    cmds = [
        ("baseline",         "Create initial hash snapshot of a file/dir"),
        ("scan",             "Compare current state against baseline"),
        ("live",             "Start real-time watchdog monitoring"),
        ("logs",             "View stored event log"),
        ("export",           "Export logs to JSON or CSV"),
        ("help",             "Show this help menu"),
        ("exit / quit",      "Exit the program"),
    ]
    for cmd, desc in cmds:
        print(f"  {GREEN}{cmd:<20}{RESET}{WHITE}{desc}{RESET}")

    print(f"\n{BOLD}{CYAN}  Options available at prompts:{RESET}")
    opts = [
        ("--algo sha256|sha1|md5", "Choose hashing algorithm (default: sha256)"),
        ("--ignore <name>",        "Add extra ignore pattern (can repeat)"),
    ]
    for opt, desc in opts:
        print(f"  {YELLOW}{opt:<30}{RESET}{WHITE}{desc}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")


def run_shell():
    """
    Main interactive REPL.  Keeps running until the user types exit/quit.
    Invalid commands show an error and re-prompt — no abrupt exits.
    """
    generate_banner()
    init_database()

    VALID_COMMANDS = {"baseline", "scan", "live", "logs", "export", "help", "exit", "quit"}

    while True:
        try:
            raw = input(f"{GRAY}fim{RESET}{WHITE}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[*] Use 'exit' to quit.{RESET}")
            continue

        if not raw:
            continue

        # Split command from inline flags
        parts   = raw.split()
        command = parts[0].lower()
        args    = parts[1:]   

        if command not in VALID_COMMANDS:
            print(f"{RED}[!] Unknown command: '{command}'. Type 'help' to see commands.{RESET}")
            continue

        if command == "help":
            show_help()

        elif command in ("exit", "quit"):
            print(f"{CYAN}[+] {WHITE}Exiting FIM. Stay safe.{RESET}\n")
            sys.exit(0)

        elif command == "baseline":
            cmd_baseline(args)

        elif command == "scan":
            cmd_scan(args)

        elif command == "live":
            cmd_live(args)

        elif command == "logs":
            cmd_logs()

        elif command == "export":
            cmd_export()


# 
#    DATABASE layr
# 

def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with WAL mode for better concurrency."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row   # lets us access columns by name
    return conn


def init_database():
    """
    Create tables if they don't exist yet.

    Tables
    ──────
    fileintegrity  → stores baseline hash + metadata, keyed by absolute path
    events         → append-only log of every integrity event
    """
    conn = get_connection()
    cur  = conn.cursor()

    # Baseline table 
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fileintegrity (
            path         TEXT PRIMARY KEY,
            filename     TEXT NOT NULL,
            algorithm    TEXT NOT NULL DEFAULT 'sha256',
            hash         TEXT NOT NULL,
            size         INTEGER NOT NULL,
            created_at   TEXT NOT NULL,
            last_modified TEXT NOT NULL,
            baseline_time TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Event / audit log table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type   TEXT NOT NULL,   -- ADDED | MODIFIED | DELETED
            path         TEXT NOT NULL,
            old_hash     TEXT,
            new_hash     TEXT,
            detail       TEXT,
            timestamp    TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()


def upsert_file(path: str, filename: str, algo: str,
                file_hash: str, size: int,
                created_at: str, last_modified: str):
    """Insert or replace a file record in the baseline table."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO fileintegrity
            (path, filename, algorithm, hash, size, created_at, last_modified, baseline_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (path, filename, algo, file_hash, size,
          created_at, last_modified, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def fetch_baseline() -> list:
    """Return all rows from the baseline table."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM fileintegrity").fetchall()
    conn.close()
    return rows


def delete_baseline_entry(path: str):
    """Remove a file from the baseline (used during scan cleanup)."""
    conn = get_connection()
    conn.execute("DELETE FROM fileintegrity WHERE path = ?", (path,))
    conn.commit()
    conn.close()


def log_event(event_type: str, path: str,
              old_hash: str = None, new_hash: str = None,
              detail: str = None):
    """
    Append an integrity event to both the DB events table
    and the plain-text log file for portability.
    """
    ts = datetime.now().isoformat()

    # DB log 
    conn = get_connection()
    conn.execute("""
        INSERT INTO events (event_type, path, old_hash, new_hash, detail, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (event_type, path, old_hash, new_hash, detail, ts))
    conn.commit()
    conn.close()

    # file log flat
    with open(LOG_FILE, "a", encoding="utf-8") as lf:
        lf.write(f"[{ts}] [{event_type}] {path}")
        if detail:
            lf.write(f" | {detail}")
        lf.write("\n")


# 
#   3 — HASHING ENGINE
# 

def hash_file(filepath: str, algorithm: str = "sha256") -> str | None:
    """
    Hash a single file using chunked reads (8 KiB).
    Returns hex digest string, or None on error.

    Handles:
      - PermissionError
      - FileNotFoundError
      - OSError (locked files, special devices, etc.)
    """
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGOS:
        print(f"{RED}[!] Unsupported algorithm '{algo}'. "
              f"Choose from: {', '.join(SUPPORTED_ALGOS)}{RESET}")
        return None

    hasher = hashlib.new(algo)

    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    except PermissionError:
        print(f"{YELLOW}[!] Permission denied — skipped: {filepath}{RESET}")
    except FileNotFoundError:
        print(f"{YELLOW}[!] File not found (may have been deleted): {filepath}{RESET}")
    except OSError as e:
        print(f"{YELLOW}[!] OS error on '{filepath}': {e}{RESET}")

    return None


def collect_files(target: str, ignores: set) -> list[str]:
    """
    Walk a file or directory and return a list of absolute file paths.
    Skips any path component that matches an ignore pattern.
    """
    target = os.path.abspath(target)

    if os.path.isfile(target):
        return [target]

    result = []
    for root, dirs, files in os.walk(target):
        # Prune ignored directories in-place so os.walk doesn't descend into them
        dirs[:] = [d for d in dirs if d not in ignores]

        for fname in files:
            if fname in ignores:
                continue
            full_path = os.path.join(root, fname)
            result.append(full_path)

    return result


# 
#  4 — COMMAND IMPLEMENTATIONS
# 

# ── Helper: resolve algorithm and ignore set from token list ──
def _parse_args(args: list) -> tuple[str, set]:
    """
    Minimal flag parser for inline command arguments.
    Returns (algorithm, ignores_set).

    Supported flags:
        --algo sha256|sha1|md5
        --ignore <name>   (repeatable)
    """
    algo    = "sha256"
    ignores = set(DEFAULT_IGNORES)
    i = 0
    while i < len(args):
        if args[i] == "--algo" and i + 1 < len(args):
            algo = args[i + 1].lower()
            i += 2
        elif args[i] == "--ignore" and i + 1 < len(args):
            ignores.add(args[i + 1])
            i += 2
        else:
            i += 1
    return algo, ignores


def _prompt_target(mode_label: str) -> str | None:
    """
    Ask user for a file or directory path.
    Loops until a valid path is entered or 'back' is typed.
    """
    print(f"{CYAN}[+] {WHITE}Enter a file or directory path. "
          f"Type 'back' to cancel.{RESET}")

    while True:
        raw = input(f"{GRAY}[#] {mode_label} path: {RESET}").strip()

        if raw.lower() == "back":
            return None

        norm = os.path.normpath(raw)

        if not os.path.exists(norm):
            print(f"{RED}[!] Path does not exist: {norm}{RESET}")
            continue

        return norm


# 
#  baseline  →  create initial snapshot
# 
def cmd_baseline(args: list):
    """
    Walk target path, hash every file, store in DB.
    Existing entries for the same path are overwritten (INSERT OR REPLACE).
    """
    algo, ignores = _parse_args(args)

    print(f"\n{BOLD}{BLUE}[*] BASELINE MODE — Algorithm: {algo.upper()}{RESET}")
    target = _prompt_target("Baseline")
    if target is None:
        return

    files = collect_files(target, ignores)
    if not files:
        print(f"{YELLOW}[!] No files found under: {target}{RESET}")
        return

    total  = len(files)
    hashed = 0
    errors = 0

    print(f"{CYAN}[+] {WHITE}Found {total} file(s). Starting baseline...{RESET}\n")

    for fpath in files:
        file_hash = hash_file(fpath, algo)
        if file_hash is None:
            errors += 1
            log_event("ERROR", fpath, detail="Hash failed during baseline")
            continue

        try:
            stat          = os.stat(fpath)
            filename      = os.path.basename(fpath)
            size          = stat.st_size
            created_at    = datetime.fromtimestamp(stat.st_ctime).isoformat()
            last_modified = datetime.fromtimestamp(stat.st_mtime).isoformat()

            upsert_file(fpath, filename, algo, file_hash,
                        size, created_at, last_modified)

            print(f"  {GREEN}[✓]{RESET} {WHITE}{fpath}{RESET}")
            print(f"      {GRAY}Hash: {file_hash}  |  Size: {size} bytes{RESET}")
            hashed += 1

        except OSError as e:
            print(f"  {RED}[!]{RESET} {WHITE}Stat failed for {fpath}: {e}{RESET}")
            errors += 1

    #>faaaaaaaaaahhhhhhhhhhhhhhhh
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"  {GREEN}Baseline complete.{RESET}")
    print(f"  {WHITE}Files hashed : {GREEN}{hashed}{RESET}")
    print(f"  {WHITE}Errors       : {RED}{errors}{RESET}")
    print(f"  {WHITE}Database     : {GRAY}{os.path.abspath(DB_PATH)}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")


# 
#  integrity check against baseline
# 
def cmd_scan(args: list):
    """
    Re-hash all files in the baseline and compare results.

    Reports:
      MODIFIED  → hash changed
      DELETED   → file no longer on disk
      ADDED     → file on disk but not in baseline (within same directory scope)
    """
    algo, ignores = _parse_args(args)

    print(f"\n{BOLD}{BLUE}[*] SCAN MODE — Checking integrity...{RESET}\n")

    baseline = fetch_baseline()
    if not baseline:
        print(f"{YELLOW}[!] Baseline is empty. Run 'baseline' first.{RESET}")
        return

    modified = []
    deleted  = []
    clean    = []

    
    for row in baseline:
        stored_path = row["path"]
        stored_hash = row["hash"]
        stored_algo = row["algorithm"]

        
        scan_algo   = algo if "--algo" in args else stored_algo

        if not os.path.exists(stored_path):
            deleted.append(stored_path)
            log_event("DELETED", stored_path,
                      old_hash=stored_hash,
                      detail="File missing from disk during scan")
            continue

        current_hash = hash_file(stored_path, scan_algo)
        if current_hash is None:
            continue   # error already printed by hash_file

        if current_hash != stored_hash:
            modified.append((stored_path, stored_hash, current_hash))
            log_event("MODIFIED", stored_path,
                      old_hash=stored_hash,
                      new_hash=current_hash,
                      detail=f"Hash mismatch detected during scan")
        else:
            clean.append(stored_path)






    baseline_paths = {row["path"] for row in baseline}
    scanned_roots  = set()
    added          = []

    for row in baseline:
        root_dir = str(Path(row["path"]).parent)
        # Only walk each unique root once
        if root_dir not in scanned_roots:
            scanned_roots.add(root_dir)
            for fpath in collect_files(root_dir, ignores):
                if fpath not in baseline_paths:
                    added.append(fpath)
                    log_event("ADDED", fpath,
                              detail="New file detected during scan")

    
    _print_scan_results(clean, modified, deleted, added)


def _print_scan_results(clean, modified, deleted, added):
    """Nicely format and print scan results to CLI."""
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{WHITE}  INTEGRITY SCAN RESULTS{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")

    if modified:
        print(f"\n{RED}{BOLD}  ⚠ MODIFIED FILES ({len(modified)}){RESET}")
        for path, old_h, new_h in modified:
            print(f"\n  {RED}[MODIFIED]{RESET} {WHITE}{path}{RESET}")
            print(f"    {GRAY}Old hash: {old_h}{RESET}")
            print(f"    {YELLOW}New hash: {new_h}{RESET}")

    if deleted:
        print(f"\n{RED}{BOLD}  ✗ DELETED FILES ({len(deleted)}){RESET}")
        for path in deleted:
            print(f"  {RED}[DELETED]{RESET}  {WHITE}{path}{RESET}")

    if added:
        print(f"\n{YELLOW}{BOLD}  + NEWLY ADDED FILES ({len(added)}){RESET}")
        for path in added:
            print(f"  {YELLOW}[ADDED]{RESET}   {WHITE}{path}{RESET}")

    if clean:
        print(f"\n{GREEN}{BOLD}  ✓ CLEAN FILES ({len(clean)}){RESET}")
        for path in clean:
            print(f"  {GREEN}[OK]{RESET}      {GRAY}{path}{RESET}")

    if not modified and not deleted and not added:
        print(f"\n  {GREEN}{BOLD}All files match baseline. No integrity violations detected.{RESET}")

    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"  {WHITE}Clean: {GREEN}{len(clean)}{RESET}  "
          f"{WHITE}Modified: {RED}{len(modified)}{RESET}  "
          f"{WHITE}Deleted: {RED}{len(deleted)}{RESET}  "
          f"{WHITE}Added: {YELLOW}{len(added)}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")


# 
#  watchdog monitoring
# 
class FIMEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler.
    On any FS event, re-hash the affected file and compare to baseline.
    """

    def __init__(self, algo: str, ignores: set):
        super().__init__()
        self.algo    = algo
        self.ignores = ignores
        self._baseline_cache = self._load_cache()

    def _load_cache(self) -> dict:
        """Load baseline into memory as { path: hash } for fast lookups."""
        rows = fetch_baseline()
        return {row["path"]: row["hash"] for row in rows}

    def _should_ignore(self, path: str) -> bool:
        parts = Path(path).parts
        return any(p in self.ignores for p in parts)

    def _alert(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        color = RED if level in ("MODIFIED", "DELETED") else YELLOW
        print(f"{GRAY}[{ts}]{RESET} {color}{BOLD}[{level}]{RESET} {WHITE}{msg}{RESET}")

    def on_modified(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        path = os.path.abspath(event.src_path)
        current_hash = hash_file(path, self.algo)
        if current_hash is None:
            return

        stored_hash = self._baseline_cache.get(path)
        if stored_hash is None:
            self._alert("ADDED", f"New file outside baseline: {path}")
            log_event("ADDED", path, new_hash=current_hash,
                      detail="Detected by watchdog (not in baseline)")
        elif current_hash != stored_hash:
            self._alert("MODIFIED", f"Hash mismatch: {path}")
            self._alert("MODIFIED", f"  Stored : {stored_hash}")
            self._alert("MODIFIED", f"  Current: {current_hash}")
            log_event("MODIFIED", path,
                      old_hash=stored_hash, new_hash=current_hash,
                      detail="Detected by watchdog")

    def on_deleted(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        path = os.path.abspath(event.src_path)
        stored_hash = self._baseline_cache.get(path)
        self._alert("DELETED", f"File removed from disk: {path}")
        log_event("DELETED", path,
                  old_hash=stored_hash,
                  detail="Detected by watchdog")

    def on_created(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        path = os.path.abspath(event.src_path)
        current_hash = hash_file(path, self.algo)
        self._alert("ADDED", f"New file detected: {path}")
        log_event("ADDED", path, new_hash=current_hash,
                  detail="Detected by watchdog")


def cmd_live(args: list):
    """Start watchdog observer on a target directory."""
    if not WATCHDOG_AVAILABLE:
        print(f"{RED}[!] 'watchdog' library not installed.{RESET}")
        print(f"{WHITE}[*] Install it with: pip install watchdog{RESET}")
        return

    algo, ignores = _parse_args(args)

    print(f"\n{BOLD}{BLUE}[*] LIVE MONITORING MODE — Algorithm: {algo.upper()}{RESET}")
    target = _prompt_target("Monitor directory")
    if target is None:
        return

    if not os.path.isdir(target):
        print(f"{RED}[!] Live mode requires a directory, not a file.{RESET}")
        return

    handler  = FIMEventHandler(algo, ignores)
    observer = Observer()
    observer.schedule(handler, target, recursive=True)
    observer.start()

    print(f"{GREEN}[+] {WHITE}Watching: {CYAN}{target}{RESET}")
    print(f"{GRAY}    Press Ctrl+C to stop monitoring.{RESET}\n")

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\n{YELLOW}[*] Live monitoring stopped.{RESET}\n")

    observer.join()


# 
#  logs
# 
def cmd_logs():
    """Print the most recent 50 events from the DB events table."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT timestamp, event_type, path, old_hash, new_hash, detail
        FROM events
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()
    conn.close()

    if not rows:
        print(f"{YELLOW}[!] No events logged yet.{RESET}")
        return

    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{WHITE}  RECENT EVENTS (last {len(rows)}){RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")

    COLOR_MAP = {
        "MODIFIED": RED,
        "DELETED":  RED,
        "ADDED":    YELLOW,
        "ERROR":    MAGENTA,
    }

    for row in reversed(rows):
        ts, etype, path, old_h, new_h, detail = row
        color = COLOR_MAP.get(etype, WHITE)
        print(f"{GRAY}[{ts}]{RESET} {color}{BOLD}[{etype}]{RESET} {WHITE}{path}{RESET}")
        if old_h:
            print(f"  {GRAY}Old: {old_h}{RESET}")
        if new_h:
            print(f"  {CYAN}New: {new_h}{RESET}")
        if detail:
            print(f"  {GRAY}Note: {detail}{RESET}")
        print()

    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")


# 
#  exporting logs to JSON or CSV
# 
def cmd_export():
    """Export the events log to JSON or CSV."""
    print(f"{CYAN}[+] {WHITE}Export format: json / csv{RESET}")
    fmt = input(f"{GRAY}[#] Format: {RESET}").strip().lower()

    if fmt not in ("json", "csv"):
        print(f"{RED}[!] Invalid format. Choose 'json' or 'csv'.{RESET}")
        return

    conn = get_connection()
    rows = conn.execute(
        "SELECT timestamp, event_type, path, old_hash, new_hash, detail FROM events ORDER BY id"
    ).fetchall()
    conn.close()

    if not rows:
        print(f"{YELLOW}[!] No events to export.{RESET}")
        return

    ts_str    = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"fim_export_{ts_str}.{fmt}"

    if fmt == "json":
        data = [
            {
                "timestamp":  r["timestamp"],
                "event_type": r["event_type"],
                "path":       r["path"],
                "old_hash":   r["old_hash"],
                "new_hash":   r["new_hash"],
                "detail":     r["detail"],
            }
            for r in rows
        ]
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    else:  # csv
        import csv
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event_type", "path",
                             "old_hash", "new_hash", "detail"])
            for r in rows:
                writer.writerow([r["timestamp"], r["event_type"], r["path"],
                                  r["old_hash"], r["new_hash"], r["detail"]])

    print(f"{GREEN}[+] {WHITE}Exported {len(rows)} event(s) to: "
          f"{CYAN}{os.path.abspath(filename)}{RESET}\n")


# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# //////////////////////////////

if __name__ == "__main__":
    if os.name == 'nt':
        os.system('color')

    run_shell()
