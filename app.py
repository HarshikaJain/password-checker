from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)

# Load password list (auto-detect file)
def load_passwords():
    try:
        # Try both filenames (flexible)
        file_path = None

        if os.path.exists("common_passwords.txt"):
            file_path = "common_passwords.txt"
        elif os.path.exists("rockyou.txt"):
            file_path = "rockyou.txt"

        if not file_path:
            raise FileNotFoundError("No password file found")

        with open(file_path, "r", encoding="latin-1") as file:
            passwords = set(line.strip().lower() for line in file if line.strip())

        print(f"✅ Loaded {len(passwords)} passwords from {file_path}")
        return passwords

    except Exception as e:
        print("⚠️ Error loading password file:", e)
        return set()

# Load once at startup
breached_passwords = load_passwords()


# Home route
@app.route("/")
def home():
    return render_template("index.html")


# Password check API
@app.route("/check", methods=["POST"])
def check_password():

    data = request.get_json()

    # Safe input handling
    if not data or "password" not in data:
        return jsonify({"error": "No password provided"}), 400

    password = data.get("password", "").strip()

    score = 0
    feedback = []
    breached = False

    # Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")

    # Uppercase
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    # Lowercase
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    # Digit
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    # Special char
    if any(c in "!@#$%^&*()" for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    # Breach check
    if password.lower() in breached_passwords:
        breached = True
        feedback.append(
            "⚠️ This password is found in real-world data breaches.\n❌ Do NOT use this password."
        )
        score = 0  # override score

    # Percentage
    total_checks = 5
    percentage = int((score / total_checks) * 100)

    # Strength
    if breached:
        strength = "Weak"
    elif percentage < 40:
        strength = "Weak"
    elif percentage < 70:
        strength = "Medium"
    else:
        strength = "Strong"

    # Response
    return jsonify({
        "percentage": percentage,
        "strength": strength,
        "feedback": feedback,
        "breached": breached
    })

# Run server
if __name__ == "__main__":
    app.run(debug=True)