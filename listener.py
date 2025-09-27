"""
Simple Listener for reverse shells — extended with background (nohup) mode
"""

MODULE_INFO = {
    "description": "Start a listener for reverse shells (multiple backends + nohup background)"
}

OPTIONS = {
    "port": {
        "type": "int",
        "description": "Port to listen on",
        "required": True,
        "default": 4444
    },
    "type": {
        "type": "choice",
        "description": "Listener type",
        "required": False,
        "choices": ["nc", "ncat", "socat", "python", "python-threaded"],
        "default": "nc"
    },
    "bind": {
        "type": "str",
        "description": "Interface to bind to (0.0.0.0 for all)",
        "required": False,
        "default": "0.0.0.0"
    },
    "log": {
        "type": "str",
        "description": "Log file to save session output (optional)",
        "required": False,
        "default": ""
    },
    "run_now": {
        "type": "bool",
        "description": "If true, try to run the listener immediately (may require external tools installed)",
        "required": False,
        "default": True
    },
    "background": {
        "type": "bool",
        "description": "If true, run the listener in background using nohup (requires run_now=True and a Unix-like OS)",
        "required": False,
        "default": False
    }
}

import subprocess
import sys
import os
import shlex

def _available(cmd):
    from shutil import which
    return which(cmd) is not None

def _run_blocking_command(cmd):
    try:
        subprocess.call(cmd, shell=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
    except Exception as e:
        print(f"[!] Error running command: {e}")

def _run_background_command(cmd):
    """
    Run command in background using nohup. Returns PID if possible (best-effort).
    """
    try:
        # Ensure nohup exists
        if not _available("nohup"):
            print("[!] 'nohup' not found in PATH — cannot background using nohup.")
            return None

        # Start the background process via shell so shell handles redirection and &
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setpgrp)
        # We return proc.pid as best-effort info (may be a shell wrapper PID)
        return proc.pid
    except Exception as e:
        print(f"[!] Failed to start background process: {e}")
        return None

def run(session, options):
    port = int(options.get("port", 4444))
    listener_type = options.get("type", "nc")
    bind_addr = options.get("bind", "0.0.0.0")
    logfile = options.get("log", "")
    run_now = bool(options.get("run_now", True))
    background = bool(options.get("background", False))
    
    print("⚠️  AUTHORIZED USE ONLY — only test on systems you own or have permission to test.")
    print(f"[*] Listener type={listener_type} on {bind_addr}:{port} (run_now={run_now}, background={background})")
    if logfile:
        print(f"[*] Session output target: {logfile}")
    print("[!] Make sure the port is not blocked by firewall and you have permission.")
    print("-" * 60)
    
    # Decide effective logfile for nohup (if empty, default nohup.out)
    nohup_log = logfile if logfile else "nohup.out"

    try:
        if listener_type == "nc":
            if not _available("nc"):
                print("[!] 'nc' not found in PATH.")
            if sys.platform == "win32":
                cmd = f"nc -lvp {port}"
            else:
                cmd = f"nc -lvnp {port}"
                if bind_addr and bind_addr != "0.0.0.0":
                    cmd = f"nc -lvnp {port} -s {shlex.quote(bind_addr)}"
            if logfile and not background:
                # If running foreground and user wants logging, pipe through tee
                cmd = f"{cmd} | tee -a {shlex.quote(logfile)}"
            if background and logfile:
                # run with nohup redirecting to logfile
                shell_cmd = f"nohup {cmd} >> {shlex.quote(nohup_log)} 2>&1 &"
                print(f"[+] Background command: {shell_cmd}")
                if run_now:
                    pid = _run_background_command(shell_cmd)
                    print(f"[+] Background starter PID: {pid}")
                else:
                    print("[+] run_now is False — not executing background command.")
            else:
                print(f"[+] Command: {cmd}")
                if run_now:
                    _run_blocking_command(cmd)
                else:
                    print("[+] run_now is False — not executing command.")
        
        elif listener_type == "ncat":
            if not _available("ncat"):
                print("[!] 'ncat' not found in PATH.")
            cmd = f"ncat -l -v -p {port}"
            if bind_addr and bind_addr != "0.0.0.0":
                cmd += f" --listen {bind_addr}:{port}"
            if not background and logfile:
                cmd = f"{cmd} | tee -a {shlex.quote(logfile)}"
            if background:
                shell_cmd = f"nohup {cmd} >> {shlex.quote(nohup_log)} 2>&1 &"
                print(f"[+] Background command: {shell_cmd}")
                if run_now:
                    pid = _run_background_command(shell_cmd)
                    print(f"[+] Background starter PID: {pid}")
                else:
                    print("[+] run_now is False — not executing background command.")
            else:
                print(f"[+] Command: {cmd}")
                if run_now:
                    _run_blocking_command(cmd)
                else:
                    print("[+] run_now is False — not executing command.")
        
        elif listener_type == "socat":
            if not _available("socat"):
                print("[!] 'socat' not found in PATH.")
            if bind_addr and bind_addr != "0.0.0.0":
                cmd = f"socat -d -d TCP-LISTEN:{port},bind={bind_addr},reuseaddr,fork STDIO"
            else:
                cmd = f"socat -d -d TCP-LISTEN:{port},reuseaddr,fork STDIO"
            if not background and logfile:
                cmd = f"{cmd} | tee -a {shlex.quote(logfile)}"
            if background:
                shell_cmd = f"nohup {cmd} >> {shlex.quote(nohup_log)} 2>&1 &"
                print(f"[+] Background command: {shell_cmd}")
                if run_now:
                    pid = _run_background_command(shell_cmd)
                    print(f"[+] Background starter PID: {pid}")
                else:
                    print("[+] run_now is False — not executing background command.")
            else:
                print(f"[+] Command: {cmd}")
                if run_now:
                    _run_blocking_command(cmd)
                else:
                    print("[+] run_now is False — not executing command.")
        
        elif listener_type == "python":
            python_file = 'listener.py'
            python_code = f'''#!/usr/bin/env python3
import socket
import sys

HOST = "{bind_addr}"
PORT = {port}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
print("[+] Python listener listening on {{}}:{{}}".format(HOST, PORT))
conn, addr = s.accept()
print("[+] Connection from", addr)
try:
    while True:
        cmd = input("$ ")
        if not conn:
            break
        if cmd.strip() == "exit":
            break
        conn.sendall(cmd.encode() + b"\\n")
        data = conn.recv(8192)
        if not data:
            break
        print(data.decode('utf-8', errors='ignore'), end='')
except KeyboardInterrupt:
    pass
finally:
    try:
        conn.close()
    except:
        pass
    s.close()
'''
            with open(python_file, 'w') as f:
                f.write(python_code)
            print(f"[+] Python listener script saved as '{python_file}'")
            if background:
                shell_cmd = f"nohup python3 {shlex.quote(python_file)} >> {shlex.quote(nohup_log)} 2>&1 &"
                print(f"[+] Background command: {shell_cmd}")
                if run_now:
                    pid = _run_background_command(shell_cmd)
                    print(f"[+] Background starter PID: {pid}")
                else:
                    print("[+] run_now is False — not executing background command.")
            else:
                if run_now:
                    print("[+] Running python listener now (Ctrl+C to stop)")
                    if logfile:
                        _run_blocking_command(f"python3 {shlex.quote(python_file)} | tee -a {shlex.quote(logfile)}")
                    else:
                        _run_blocking_command(f"python3 {shlex.quote(python_file)}")
                else:
                    print("[+] run_now is False — not executing command.")
        
        elif listener_type == "python-threaded":
            python_file = 'listener_threaded.py'
            python_code = f'''#!/usr/bin/env python3
import socket, threading

HOST = "{bind_addr}"
PORT = {port}

def handle_client(client, addr):
    print("[+] Connected:", addr)
    try:
        while True:
            cmd = input(f"({{addr[0]}}:{{addr[1]}}) $ ")
            if cmd.strip() == "exit":
                break
            try:
                client.sendall(cmd.encode() + b"\\n")
                resp = client.recv(8192)
                print(resp.decode('utf-8', errors='ignore'))
            except Exception as e:
                print("[!] Client comms error:", e)
                break
    finally:
        client.close()

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((HOST, PORT))
listener.listen(5)
print("[+] Threaded listener running on {{}}:{{}}".format(HOST, PORT))

try:
    while True:
        client, addr = listener.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()
except KeyboardInterrupt:
    print("\\n[*] Stopping listener")
finally:
    listener.close()
'''
            with open(python_file, 'w') as f:
                f.write(python_code)
            print(f"[+] Threaded python listener saved as '{python_file}'")
            if background:
                shell_cmd = f"nohup python3 {shlex.quote(python_file)} >> {shlex.quote(nohup_log)} 2>&1 &"
                print(f"[+] Background command: {shell_cmd}")
                if run_now:
                    pid = _run_background_command(shell_cmd)
                    print(f"[+] Background starter PID: {pid}")
                else:
                    print("[+] run_now is False — not executing background command.")
            else:
                if run_now:
                    print("[+] Running threaded listener now (Ctrl+C to stop)")
                    if logfile:
                        _run_blocking_command(f"python3 {shlex.quote(python_file)} | tee -a {shlex.quote(logfile)}")
                    else:
                        _run_blocking_command(f"python3 {shlex.quote(python_file)}")
                else:
                    print("[+] run_now is False — not executing command.")
        
        else:
            print(f"[!] Unknown listener type: {listener_type}")
        
        return True

    except KeyboardInterrupt:
        print("\n[*] Listener stopped")
        return True
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
