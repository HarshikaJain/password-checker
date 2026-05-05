from flask import Flask, render_template, request, jsonify
import hashlib
import requests

app = Flask(__name__)

# -------------------------------
# 🔐 REAL BREACH CHECK (HIBP API)
# -------------------------------
def check_pwned(password):
    try:
        # Convert password → SHA1 hash
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()

        # Split hash (k-anonymity)
        prefix = sha1[:5]
        suffix = sha1[5:]

        # API request
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code != 200:
            return False

        # Compare suffix with returned hashes
        hashes = (line.split(":") for line in response.text.splitlines())

        for h, count in hashes:
            if h == suffix:
                return True  # password found in breach

        return False

    except Exception as e:
        print("Error checking breach:", e)
        return False


# -------------------------------
# 🏠 HOME ROUTE
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# 🔍 PASSWORD CHECK API
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

    # 🚨 REAL BREACH CHECK
    if password:
        breached = check_pwned(password)

        if breached:
            feedback.append(
                "⚠️ This password has appeared in real-world data breaches. Do NOT use it."
            )
            score = 0  # override score

    # 📊 Percentage
    total_checks = 5
    percentage = int((score / total_checks) * 100)

    # 💪 Strength
    if breached:
        strength = "Weak"
    elif percentage < 40:
        strength = "Weak"
    elif percentage < 70:
        strength = "Medium"
    else:
        strength = "Strong"

    # 📦 Response
    return jsonify({
        "percentage": percentage,
        "strength": strength,
        "feedback": feedback,
        "breached": breached
    })


# -------------------------------
# 🚀 RUN SERVER
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)