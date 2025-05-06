import streamlit as st
import json
import os
import base64
import time
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ------------------ Constants ------------------ #
USER_DB = "users.json"
MAX_ATTEMPTS = 3
SALT = b'streamlit_secure_vault'  # Use a stronger one in production

# ------------------ Utilities ------------------ #
def load_users():
    if not os.path.exists(USER_DB):
        with open(USER_DB, "w") as f:
            json.dump({}, f)
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(data):
    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=2)

def get_fernet_key(password: str) -> bytes:
    """Derives a Fernet-compatible key from the password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: str, key: bytes) -> str:
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt_data(token: str, key: bytes) -> str:
    try:
        return Fernet(key).decrypt(token.encode()).decode()
    except:
        return None

# ------------------ Session State ------------------ #
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.attempts = 0

# ------------------ UI Design ------------------ #
st.set_page_config(page_title="Secure Vault", layout="centered")
st.markdown("""
    <style>
    body, .stApp { background-color: #0E1117; color: white; }
    .stButton>button { background-color: #4CAF50; color: white; }
    .stButton>button:hover { background-color: #45a049; }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Secure Data Vault")

# ------------------ Authentication ------------------ #
users = load_users()

def register_user(username, password):
    if username in users:
        return False
    key = get_fernet_key(password).decode()
    users[username] = {
        "key": key,
        "data": {},
        "timestamp": str(datetime.datetime.now())
    }
    save_users(users)
    return True

def authenticate_user(username, password):
    if username not in users:
        return False
    stored_key = users[username]["key"]
    input_key = get_fernet_key(password).decode()
    return stored_key == input_key

# ------------------ Navigation ------------------ #
menu = ["Login", "Register", "Vault"]
choice = st.sidebar.radio("Menu", menu)

# ------------------ Register ------------------ #
if choice == "Register":
    st.subheader("🧾 Create New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if register_user(new_user, new_pass):
            st.success("✅ Account created. Please login.")
        else:
            st.error("❌ Username already exists.")

# ------------------ Login ------------------ #
elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.attempts = 0
            st.success("✅ Login successful")
            time.sleep(1)
            st.rerun()
        else:
            st.session_state.attempts += 1
            attempts_left = MAX_ATTEMPTS - st.session_state.attempts
            st.error(f"❌ Incorrect credentials. {attempts_left} attempts left.")
            if st.session_state.attempts >= MAX_ATTEMPTS:
                st.warning("🚫 Too many failed attempts. Please try later.")
                st.stop()

# ------------------ Vault ------------------ #
elif choice == "Vault":
    if not st.session_state.authenticated:
        st.warning("🔐 Please log in to access the vault.")
        st.stop()

    st.subheader(f"🧰 Welcome, {st.session_state.username}")
    data_entry = st.text_area("Data to encrypt")
    password_key = st.text_input("Your vault password again", type="password")
    action = st.radio("Action", ["Encrypt & Store", "Retrieve Data", "Logout"])

    user_key = get_fernet_key(password_key)

    if action == "Encrypt & Store":
        if st.button("Save to Vault"):
            if data_entry and password_key:
                enc = encrypt_data(data_entry, user_key)
                ts = str(datetime.datetime.now())
                users[st.session_state.username]["data"][ts] = enc
                save_users(users)
                st.success("✅ Data encrypted and saved!")
                st.code(enc, language="text")
            else:
                st.error("❗ Enter both data and passphrase.")

    elif action == "Retrieve Data":
        stored = users[st.session_state.username]["data"]
        if not stored:
            st.info("📭 No stored data found.")
        else:
            sel_ts = st.selectbox("Select Entry Timestamp", list(stored.keys()))
            if st.button("Decrypt"):
                enc_data = stored[sel_ts]
                dec = decrypt_data(enc_data, user_key)
                if dec:
                    st.success("🔓 Decryption successful")
                    st.code(dec, language="text")
                else:
                    st.error("❌ Invalid key or data corrupt")

    elif action == "Logout":
        st.session_state.authenticated = False
        st.session_state.username = None
        st.success("👋 Logged out")
        st.rerun()
