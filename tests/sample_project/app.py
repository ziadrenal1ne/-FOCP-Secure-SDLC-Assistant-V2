"""Sample vulnerable application for testing FOCP Secure SDLC Assistant."""

from flask import Flask, request, session
import hashlib
import jwt
import os

app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "hardcoded-secret-key-12345"

DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # Simulated query execution
    if password == "admin":
        session["user"] = username
        return "Logged in"
    return "Failed"

@app.route("/admin/users")
def admin_users():
    return "Admin panel - all users"

@app.route("/api/data")
def get_data():
    user_id = request.args.get("id")
    query = "SELECT * FROM data WHERE user_id = " + user_id
    return query

@app.route("/render")
def render_page():
    name = request.args.get("name", "")
    return f"<html><body>Hello {name}</body></html>"

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    file.save(f"/var/www/uploads/{file.filename}")
    return "Uploaded"

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    import requests
    return requests.get(url).text

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
