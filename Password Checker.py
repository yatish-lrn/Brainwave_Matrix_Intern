import re


def password_strength(password):
    # Initialize score and feedback messages
    score = 0
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters.")
    elif len(password) >= 8:
        score += 1  # Give points for good length

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters for strength.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters for strength.")

    # Check for numbers
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Include numbers to make the password stronger.")

    # Check for special characters
    if re.search(r"[@$!%*?&#]", password):
        score += 1
    else:
        feedback.append("Use special characters for better security.")

    # Check for repetition and common patterns
    if re.search(r"(.)\1{2,}", password):
        feedback.append("Avoid using repeated characters.")

    # Determine password strength
    if score == 5:
        strength = "Strong"
    elif 3 <= score < 5:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {"strength": strength, "score": score, "feedback": feedback}


# Test the function
password = "YATI2004@15"
result = password_strength(password)
print("Password Strength:", result["strength"])
print("Score:", result["score"])
print("Feedback:", result["feedback"])

