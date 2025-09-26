#!/usr/bin/python3
"""
mini-msf.py — Simple modular CLI framework in Python (safe, educational)

Perubahan/Perbaikan utama:
- Memisahkan modul contoh ke folder `examples/` (tidak lagi disisipkan di file utama).
- Memindai kedua folder `modules/` dan `examples/` tanpa mengimpor modul saat `show modules` (lazy metadata read).
- Menambahkan perintah `scan` untuk merefresh daftar modul.
- `show modules [filter]` mendukung filter sederhana (mis. `show modules aux` atau `show modules examples`).
- Semua modul diuji saat `use <key>` (import lazy) sehingga `show` cepat.
- Run modul dijaga dalam try/except agar REPL tidak crash.

Cara pakai:
1. Simpan file ini sebagai `mini-msf.py`.
2. Jalankan: `python3 mini-msf.py`.
3. Perintah penting: `show modules [filter]`, `use <module>`, `options`, `set <opt> <val>`, `run`, `back`, `scan`, `exit`.

Catatan keamanan: framework ini tidak mengandung kode yang bersifat eksploit atau backdoor. Jika menambahkan modul ber-IO (jaringan/file), gunakan hanya untuk target yang kamu miliki izin eksplisit.
"""
import os
import sys
import shlex
import importlib.util
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

# --------- configurable paths ----------
BASE_DIR = Path(__file__).parent
MODULE_DIR = BASE_DIR / "modules"
EXAMPLES_DIR = BASE_DIR / "examples"
METADATA_READ_LINES = 120  # how many lines to scan for metadata

@dataclass
class ModuleInstance:
    name: str
    module: Any
    options: Dict[str, Any] = field(default_factory=dict)

    def set_option(self, key: str, value: Any):
        if key in self.module.OPTIONS:
            self.options[key] = value
        else:
            raise KeyError(f"Unknown option '{key}'")

    def get_options(self):
        opts = {}
        for k, meta in self.module.OPTIONS.items():
            opts[k] = {"value": self.options.get(k, meta.get("default")), **meta}
        return opts

    def run(self, session):
        return self.module.run(session, self.options)


class MiniMSF:
    def __init__(self):
        self.modules: Dict[str, Path] = {}  # key -> path
        self.metadata: Dict[str, Dict[str, Any]] = {}  # key -> metadata
        self.loaded_module: Optional[ModuleInstance] = None
        self.session = {"user": os.getlogin() if hasattr(os, "getlogin") else "unknown"}
        self.scan_modules()

    def scan_modules(self):
        """Scan module files in both MODULE_DIR and EXAMPLES_DIR and read lightweight metadata without importing.
        Keys are namespaced by folder: 'modules/<rel>' and 'examples/<rel>' to avoid collisions.
        """
        self.modules = {}
        self.metadata = {}
        MODULE_DIR.mkdir(exist_ok=True)
        EXAMPLES_DIR.mkdir(exist_ok=True)

        for folder, prefix in ((MODULE_DIR, "modules"), (EXAMPLES_DIR, "examples")):
            for p in folder.rglob("*.py"):
                rel = str(p.relative_to(folder)).replace(os.sep, "/")[:-3]
                key = f"{prefix}/{rel}"
                self.modules[key] = p
                self.metadata[key] = self._read_metadata_from_file(p)

    def _read_metadata_from_file(self, path: Path) -> Dict[str, Any]:
        data = {"description": "", "options": []}
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                lines = []
                for _ in range(METADATA_READ_LINES):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                header_text = "".join(lines)
            # find MODULE_INFO = { ... }
            m = re.search(r"MODULE_INFO\s*=\s*{([^}]*)}", header_text, re.DOTALL)
            if m:
                inside = m.group(1)
                mdesc = re.search(r"['\"]description['\"]\s*:\s*['\"]([^'\"]+)['\"]", inside)
                if mdesc:
                    data["description"] = mdesc.group(1).strip()
            # OPTIONS keys
            mo = re.search(r"OPTIONS\s*=\s*{([^}]*)}", header_text, re.DOTALL)
            if mo:
                inside_o = mo.group(1)
                keys = re.findall(r"['\"]([A-Za-z0-9_]+)['\"]\s*:", inside_o)
                data["options"] = keys
            # fallback: module-level docstring first line
            if not data["description"]:
                mdoc = re.search(r'^(\s)*("""|\'\'\')(.+?)(\2)', header_text, re.DOTALL | re.MULTILINE)
                if mdoc:
                    first_line = mdoc.group(3).strip().splitlines()[0].strip()
                    data["description"] = first_line
        except Exception:
            pass
        return data

    def import_module(self, key: str):
        if key not in self.modules:
            raise KeyError("Module not found")
        path = self.modules[key]
        spec = importlib.util.spec_from_file_location(f"plugin_{key.replace('/', '_')}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # validate API
        if not hasattr(mod, "MODULE_INFO") or not hasattr(mod, "OPTIONS") or not hasattr(mod, "run"):
            raise RuntimeError("Invalid module API. require MODULE_INFO, OPTIONS, run()")
        return mod

    # ------- REPL commands ----------
    def cmd_show(self, args):
        # allow: show modules [filter]
        if len(args) == 0 or args[0] == "modules":
            filt = args[1] if len(args) > 1 else None
            print("Available modules:")
            keys = sorted(self.modules.keys())
            if filt:
                keys = [k for k in keys if filt in k]
            for k in keys:
                meta = self.metadata.get(k, {})
                desc = meta.get("description") or "(no description)"
                print(f"  {k:30} {desc}")
        else:
            print("Usage: show modules [filter]")

    def cmd_use(self, args):
        if not args:
            print("Usage: use <module>")
            return
        key = args[0]
        try:
            mod = self.import_module(key)
        except Exception as e:
            print(f"Error loading module: {e}")
            return
        inst = ModuleInstance(name=key, module=mod)
        # initialize defaults
        for k, meta in mod.OPTIONS.items():
            if "default" in meta:
                inst.options[k] = meta["default"]
        self.loaded_module = inst
        print(f"Loaded module {key}")

    def cmd_options(self, args):
        if not self.loaded_module:
            print("No module loaded. use <module> to load.")
            return
        print(f"Options for {self.loaded_module.name}:")
        opts = self.loaded_module.get_options()
        print("  Name         Current    Required    Description")
        for k, v in opts.items():
            cur = v["value"]
            req = "yes" if v.get("required") else "no"
            desc = v.get("description", "")
            print(f"  {k:12} {str(cur):10} {req:10} {desc}")

    def cmd_set(self, args):
        if not self.loaded_module:
            print("No module loaded.")
            return
        if len(args) < 2:
            print("Usage: set <option> <value>")
            return
        opt = args[0]
        val = " ".join(args[1:])
        try:
            self.loaded_module.set_option(opt, val)
            print(f"{opt} => {val}")
        except KeyError as e:
            print(e)

    def cmd_run(self, args):
        if not self.loaded_module:
            print("No module loaded.")
            return
        # check required options
        missing = []
        for k, meta in self.loaded_module.module.OPTIONS.items():
            if meta.get("required") and self.loaded_module.options.get(k) in (None, ""):
                missing.append(k)
        if missing:
            print("Missing required options:", ", ".join(missing))
            return
        try:
            self.loaded_module.run(self.session)
        except Exception as e:
            print("Module execution error:", e)

    def cmd_back(self, args):
        if self.loaded_module:
            print(f"Unload module {self.loaded_module.name}")
            self.loaded_module = None
        else:
            print("No module loaded.")

    def cmd_scan(self, args):
        self.scan_modules()
        print(f"Scanned {len(self.modules)} modules.")

    def repl(self):
        print("mini-msf (safe) — type 'help' for commands")
        while True:
            try:
                prompt = f"mini-msf({self.loaded_module.name})> " if self.loaded_module else "mini-msf> "
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line.strip():
                continue
            parts = shlex.split(line)
            cmd = parts[0]
            args = parts[1:]
            if cmd in ("exit", "quit"):
                break
            elif cmd == "help":
                print("Commands: show modules [filter] | use <module> | options | set <opt> <val> | run | back | scan | exit")
            elif cmd == "show":
                self.cmd_show(args)
            elif cmd == "use":
                self.cmd_use(args)
            elif cmd == "options":
                self.cmd_options(args)
            elif cmd == "set":
                self.cmd_set(args)
            elif cmd == "run":
                self.cmd_run(args)
            elif cmd == "back":
                self.cmd_back(args)
            elif cmd == "scan":
                self.cmd_scan(args)
            else:
                print("Unknown command. type 'help'")


# --------- create example modules in examples/ if missing (kept separate) ----------
EXAMPLE_MODULES = {
    "recon/sysinfo.py": '''"""
recon/sysinfo — safe module: print local system info
"""
import platform
MODULE_INFO = {"name": "recon/sysinfo", "description": "Print local system information"}
OPTIONS = {
    "VERBOSE": {"required": False, "default": "true", "description": "Verbose output"},
}

def run(session, options):
    print("System info:")
    print("  User:", session.get("user"))
    print("  Platform:", platform.platform())
    print("  Machine:", platform.machine())
    print("  Processor:", platform.processor())
    print("  Python:", platform.python_version())
''',
    "aux/echo.py": '''"""
aux/echo — safe module: echo input string
"""
MODULE_INFO = {"name": "aux/echo", "description": "Echo string back (safe)"}
OPTIONS = {
    "MSG": {"required": True, "default": "", "description": "Message to echo"},
}

def run(session, options):
    msg = options.get("MSG", "")
    print("ECHO:", msg)
''',
    "aux/netinfo.py": '''"""
aux/netinfo — safe module: shows local network interfaces & IPs (read-only)
"""
import socket
try:
    import psutil
except Exception:
    psutil = None
MODULE_INFO = {"name": "aux/netinfo", "description": "Show local network interfaces (read-only)"}
OPTIONS = {}

def run(session, options):
    try:
        if psutil:
            ifaces = psutil.net_if_addrs()
            for ifname, addrs in ifaces.items():
                print(f"{ifname}:")
                for a in addrs:
                    print("  ", a.family, a.address)
        else:
            print("Hostname:", socket.gethostname())
            try:
                print("Local IP:", socket.gethostbyname(socket.gethostname()))
            except Exception:
                print("Local IP: unknown")
    except Exception as e:
        print("netinfo error:", e)
'''
}


def ensure_example_modules():
    EXAMPLES_DIR.mkdir(exist_ok=True, parents=True)
    for rel, content in EXAMPLE_MODULES.items():
        p = EXAMPLES_DIR / rel
        if not p.exists():
            p.parent.mkdir(exist_ok=True, parents=True)
            p.write_text(content)


# --------- main ----------

def main():
    ensure_example_modules()
    app = MiniMSF()
    try:
        app.repl()
    except Exception as e:
        print("Fatal error:", e)
    print("Goodbye.")


if __name__ == "__main__":
    main()
