import re
import streamlit as st
import random
import string

# Common password blacklist
COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "sunshine", "password1", "123456789"]

# Function to generate a strong password
def generate_strong_password(length=12):
    """Generate a strong password with a mix of uppercase, lowercase, digits, and special characters."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Function to check password strength
def check_password_strength(password):
    score = 0
    feedback = []
    
    # Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")
    
    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Include both uppercase and lowercase letters.")
    
    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")
    
    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")
    
    # Strength Rating
    if score == 4:
        return "✅ Strong Password!", feedback, score
    elif score == 3:
        return "⚠️ Moderate Password - Consider adding more security features.", feedback, score
    else:
        return "❌ Weak Password - Improve it using the suggestions above.", feedback, score

# Function to get strength color and label
def get_strength_color(score):
    if score == 4:
        return "green", "Strong"
    elif score == 3:
        return "orange", "Moderate"
    else:
        return "red", "Weak"

# Main function
def main():
    st.set_page_config(page_title="Password Strength Meter", page_icon="🔐", layout="centered")
    
    # Custom CSS for styling and animations
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
    
    body {
        font-family: 'Poppins', sans-serif;
        background-color: #f0f2f6;
    }
    
    .stApp {
        max-width: 800px;
        margin: auto;
        padding: 20px;
        border: 2px solid #4CAF50;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        background-color: black;
        animation: fadeIn 1s ease-in-out;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        font-size: 16px;
        transition: background-color 0.3s ease;
        margin-top: 10px;
    }
    
    .stButton>button:hover {
        background-color: #45a049;
    }
    
    .stTextInput>div>div>input {
        border-radius: 5px;
        border: 1px solid #4CAF50;
        padding: 10px;
        font-size: 16px;
        margin-bottom: 10px;
    }
    
    .stMarkdown h1 {
        color: #4CAF50;
        text-align: center;
        animation: slideIn 1s ease-in-out;
    }
    
    @keyframes slideIn {
        from { transform: translateY(-20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    
    .feedback-message {
        animation: fadeIn 0.5s ease-in-out;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🔐 Password Strength Meter")
    st.write("Check the strength of your password and get improvement suggestions!")
    
    # Password input
    password = st.text_input("Enter your password:", type="password", key="password_input")
    
    # Password generator section
    st.markdown("---")
    st.markdown("### Generate a Strong Password")
    
    if st.button("Generate Strong Password", key="generate_button"):
        generated_password = generate_strong_password()
        st.text_input("Generated Password:", value=generated_password, type="password", key="generated_password")
        st.markdown(f'<button onclick="navigator.clipboard.writeText(\'{generated_password}\')">Copy to Clipboard</button>', unsafe_allow_html=True)
    
    # Password strength feedback
    if password:
        # Check if password is in the common passwords list
        if password.lower() in COMMON_PASSWORDS:
            st.error("❌ This password is too common and weak. Please choose a different one.")
        else:
            strength, feedback, score = check_password_strength(password)
            color, label = get_strength_color(score)
            
            # Visual strength bar
            st.markdown(f"""
                <div style="background-color: {color}; height: 10px; width: {score * 25}%; border-radius: 5px; margin: 10px 0;"></div>
                <p style="color: {color}; font-weight: bold;">{label}</p>
            """, unsafe_allow_html=True)
            
            # Password complexity breakdown
            st.markdown("### Password Complexity Breakdown")
            criteria = {
                "Length ≥ 8": len(password) >= 8,
                "Uppercase": re.search(r"[A-Z]", password) is not None,
                "Lowercase": re.search(r"[a-z]", password) is not None,
                "Digit": re.search(r"\d", password) is not None,
                "Special Character": re.search(r"[!@#$%^&*]", password) is not None,
            }
            for criterion, met in criteria.items():
                icon = "✅" if met else "❌"
                st.markdown(f"{icon} {criterion}")
            
            # Feedback messages with animation
            st.markdown("### Feedback")
            for suggestion in feedback:
                st.markdown(f'<p class="feedback-message">{suggestion}</p>', unsafe_allow_html=True)

# Run the app
if __name__ == "__main__":
    main()