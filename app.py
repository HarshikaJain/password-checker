import hashlib
import requests
import math
import random
import string
import re
import os
from datetime import datetime
from functools import lru_cache
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# --- DB CONFIGURATION (Level 8) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_analytics.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class SecurityAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Store a truncated hash for privacy-safe tracking
    pwd_fingerprint = db.Column(db.String(64), index=True)
    entropy = db.Column(db.Float)
    strength = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# --- SECURITY UTILITIES ---

def load_common_passwords():
    """Level 10: Dictionary Attack Simulation"""
    try:
        with open('common_passwords.txt', 'r') as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        return set()

COMMON_PWD_SET = load_common_passwords()

@lru_cache(maxsize=500)
def check_pwned_api(password):
    """k-Anonymity Breach Detection"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        return any(line.split(":")[0] == suffix for line in res.text.splitlines())
    except: return False

def get_crack_time_text(entropy):
    """Level 10: Quantitative Risk Assessment"""
    if entropy == 0: return "Instant"
    # Assuming 10 billion guesses/sec
    seconds = (2**entropy) / 10**10
    if seconds < 1: return "Sub-second"
    if seconds < 3600: return f"{int(seconds/60)} minutes"
    if seconds < 86400: return f"{int(seconds/3600)} hours"
    if seconds < 31536000: return f"{int(seconds/86400)} days"
    return f"{int(seconds/31536000):,} years"

# --- CORE LOGIC ---

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    password = data.get("password", "")
    
    # 1. Dictionary Check
    is_common = password.lower() in COMMON_PWD_SET
    
    # 2. Entropy Math (Level 7)
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 32
    
    entropy = round(len(password) * math.log2(pool), 2) if pool > 0 else 0
    
    # 3. Breach Check
    breached = check_pwned_api(password)
    
    # 4. Generate Smart Feedback
    feedback = []
    if is_common: feedback.append("❌ This is a known common password.")
    if len(password) < 12: feedback.append("💡 Length is key: aim for 12+ characters.")
    if re.search(r'(.)\1\1', password): feedback.append("⚠️ Avoid repeating characters (e.g., 'aaa').")
    if breached: feedback.append("🚨 WARNING: This password was found in a public data leak!")

    # 5. Determine Strength
    if breached or is_common or entropy < 40:
        strength = "Weak"
        percent = 25
    elif entropy < 70:
        strength = "Medium"
        percent = 60
    else:
        strength = "Strong"
        percent = 100

    # 6. Log Audit (Level 8)
    fingerprint = hashlib.sha256(password.encode()).hexdigest()
    audit = SecurityAudit(pwd_fingerprint=fingerprint, entropy=entropy, strength=strength)
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "percentage": percent,
        "strength": strength,
        "entropy": entropy,
        "crack_time": get_crack_time_text(entropy),
        "feedback": feedback,
        "breached": breached
    })

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/generate")
def generate():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return jsonify({"password": ''.join(random.choice(chars) for _ in range(16))})

if __name__ == "__main__":
    app.run(debug=True)