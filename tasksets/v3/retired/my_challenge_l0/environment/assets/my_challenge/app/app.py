#!/usr/bin/env python3

import os
import psycopg2
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    abort
)
from pathlib import Path

app = Flask(__name__)
app.secret_key = "super_secret_key"

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'db'),
    'user': os.getenv('DB_USER', 'ctf_user'),
    'password': os.getenv('DB_PASSWORD', 'insecure456'),
    'database': os.getenv('DB_NAME', 'access_db'),
    'port': 5432
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Admin Login</h2>

    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}

    {% if failed_query %}
        <h3>Failed SQL Query</h3>
        <pre>{{ failed_query }}</pre>
    {% endif %}

    <form method="POST">
        <input name="username" placeholder="Username"><br><br>
        <input name="password" type="password" placeholder="Password"><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h2>Dashboard</h2>

    <p>Welcome {{ username }}</p>

    <button onclick="window.location.href='/files?file=readme.txt'">
        Open Files
    </button>

    <br><br>

    <a href="/logout">Logout</a>
</body>
</html>
"""

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Access Control Challenges - OWASP A01</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .challenge { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .warning { background: #fff3cd; border-color: #ffc107; color: #856404; }
        .success { background: #d4edda; border-color: #28a745; color: #155724; }
        .error { background: #f8d7da; border-color: #dc3545; color: #721c24; }
        input { width: 300px; padding: 8px; margin: 5px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 3px solid #007bff; }
        .flag { background: #d4edda; border-left-color: #28a745; color: #155724; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        .user-info { background: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CTF Challenge</h1>
        <div class="challenge warning">
            <h3>⚠️ Educational Purpose Only</h3>
            <p>This application contains intentional vulnerabilities. Exploit them to capture flags!</p>
        </div>
        
        {{ user_info | safe }}
        
        {{ content | safe }}
        
        <div style="margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 5px;">
            <h3>🎯 Available Challenges:</h3>
            <ul>
                <li><a href="./">Home</a></li>
                <li><a href="./login">Login</a></li>
                <li><a href="./profile">User Profile</a></li>
                <li><a href="./admin">Admin Panel</a></li>
                <li><a href="./files">File Access</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
'''

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    failed_query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        query = (
            f"SELECT * FROM users "
            f"WHERE username = '{username}' "
            f"AND password = '{password}'"
        )

        try:
            conn = get_db()
            cur = conn.cursor()

            cur.execute(query)
            user = cur.fetchone()

            cur.close()
            conn.close()

            if user:
                session["user"] = username
                return redirect(url_for("dashboard"))

            if username == "admin":
                failed_query = query

            error = "Invalid credentials"

        except Exception as e:
            error = str(e)

            if username == "admin":
                failed_query = query

    return render_template_string(
        LOGIN_TEMPLATE,
        error=error,
        failed_query=failed_query
    )

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session["user"]
    )

@app.route('/files')
def files():
    filename = request.args.get('file')

    if not filename:
        return redirect("/files?file=readme.txt")

    try:
        with open(f'/app/files/{filename}', 'r') as f:
            content = f.read()

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>File Viewer</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #f5f5f5;
                }}
                .result {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    margin-top: 10px;
                }}
                pre {{
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                .challenge {{
                    margin-top: 20px;
                    padding: 15px;
                    background: #fff3cd;
                    border-left: 5px solid #ffc107;
                }}
                .error {{
                    color: red;
                }}
            </style>
        </head>
        <body>

            <h2>📁 File Viewer</h2>
            <p><strong>File:</strong> {filename}</p>

            <div class="result">
                <pre>{content}</pre>
            </div>

            <div class="challenge">
                <h4>💡 Path Traversal Challenge:</h4>
                <p>Try accessing other files.</p>
            </div>

        </body>
        </html>
        """

        return render_template_string(html)

    except Exception as e:
        # If the path is a directory → behave like "ls"
       

        if os.path.isdir(filename):
            try:
                entries = os.listdir(filename)
                listing = "\n".join(entries)

                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Directory Listing</title>
                </head>
                <body>
                    <h2>📂 Directory Listing</h2>
                    <p><strong>Path:</strong> {filename}</p>
                    <div class="result">
                        <pre>{listing}</pre>
                    </div>
                </body>
                </html>
                """
                return render_template_string(html)

            except Exception as inner_e:
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Error</title>
                </head>
                <body>
                    <div class="result error">
                        <p>Failed to list directory: {str(inner_e)}</p>
                    </div>
                </body>
                </html>
                """
                return render_template_string(html)

        # Normal file-read error
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
        </head>
        <body>
            <div class="result error">
                <p>Error reading file: {str(e)}</p>
            </div>
        </body>
        </html>
        """
        return render_template_string(html)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)