from flask import Flask, render_template, request, jsonify
import hashlib
import requests
import math
import random
import string
from functools import lru_cache

app = Flask(__name__)

# -------------------------------
# 🔐 BREACH CHECK (HIBP API)
# -------------------------------
@lru_cache(maxsize=500)
def check_pwned(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": "CyberSmart-App"}

        res = requests.get(url, headers=headers, timeout=5)

        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True

        return False
    except:
        return False


# -------------------------------
# 🧠 ENTROPY
# -------------------------------
def calculate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in "!@#$%^&*()_+-=[]{}" for c in password): pool += 32

    if pool == 0:
        return 0

    return round(len(password) * math.log2(pool), 2)


# -------------------------------
# 🔐 PASSWORD GENERATOR
# -------------------------------
def generate_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(12))


# -------------------------------
# 🏠 HOME
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# 🔍 CHECK
# -------------------------------
@app.route("/check", methods=["POST"])
def check_password():

    data = request.get_json()
    password = data.get("password", "").strip()

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Minimum 8 characters required")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letter")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letter")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add number")

    if any(c in "!@#$%^&*" for c in password):
        score += 1
    else:
        feedback.append("Add special character")

    entropy = calculate_entropy(password)
    breached = check_pwned(password)

    if breached:
        feedback.append("⚠️ Found in data breaches!")
        score = 0

    percentage = int((score / 5) * 100)

    if breached or entropy < 40:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    else:
        strength = "Strong"

    return jsonify({
        "percentage": percentage,
        "strength": strength,
        "entropy": entropy,
        "feedback": feedback,
        "breached": breached
    })


# -------------------------------
# 🔐 GENERATE PASSWORD
# -------------------------------
@app.route("/generate")
def generate():
    return jsonify({"password": generate_password()})


# -------------------------------
# 🚀 RUN
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)