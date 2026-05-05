from flask import Flask, render_template, request, jsonify
import hashlib
import requests
import math

app = Flask(__name__)

# -------------------------------
# 🔐 REAL BREACH CHECK (HIBP API)
# -------------------------------
def check_pwned(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code != 200:
            return False

        hashes = (line.split(":") for line in response.text.splitlines())

        for h, count in hashes:
            if h == suffix:
                return True

        return False

    except:
        return False


# -------------------------------
# 🧠 ENTROPY CALCULATION
# -------------------------------
def calculate_entropy(password):
    pool = 0

    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in "!@#$%^&*()" for c in password):
        pool += 32

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)
    return int(entropy)


# -------------------------------
# 🏠 HOME
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# 🔍 PASSWORD CHECK
# -------------------------------
@app.route("/check", methods=["POST"])
def check_password():

    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"error": "No password provided"}), 400

    password = data.get("password", "").strip()

    score = 0
    feedback = []
    breached = False

    # 🔢 Length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")

    # 🔤 Uppercase
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    # 🔡 Lowercase
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    # 🔢 Numbers
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    # 🔐 Special characters
    if any(c in "!@#$%^&*()" for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    # 🧠 ENTROPY
    entropy = calculate_entropy(password)

    # 🚨 BREACH CHECK
    if password:
        breached = check_pwned(password)
        if breached:
            feedback.append(
                "⚠️ This password has appeared in real-world data breaches. Do NOT use it."
            )
            score = 0

    # 📊 RULE-BASED %
    rule_percentage = int((score / 5) * 100)

    # 🧠 ENTROPY-BASED STRENGTH
    if entropy < 40:
        entropy_strength = "Weak"
    elif entropy < 60:
        entropy_strength = "Medium"
    else:
        entropy_strength = "Strong"

    # 🎯 FINAL STRENGTH (combined logic)
    if breached:
        strength = "Weak"
    elif entropy_strength == "Strong" and rule_percentage > 80:
        strength = "Strong"
    elif entropy_strength == "Medium":
        strength = "Medium"
    else:
        strength = "Weak"

    # 📦 RESPONSE
    return jsonify({
        "percentage": rule_percentage,
        "strength": strength,
        "entropy": entropy,
        "feedback": feedback,
        "breached": breached
    })


# -------------------------------
# 🚀 RUN
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)