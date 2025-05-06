import streamlit as st
import datetime
import json
import time
import hashlib
import base64

# Constants
MASTER_PASSWORD = "admin123"  # In production, use environment variables
MAX_ATTEMPTS = 3

# Simplified Encryption Utilities (XOR-based)
def generate_key(passkey: str) -> bytes:
    """Generate a key from passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).digest()

def xor_encrypt(text: str, passkey: str) -> str:
    """Simple XOR encryption"""
    key = generate_key(passkey)
    encrypted = []
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        encrypted_char = chr(ord(char) ^ key_char)
        encrypted.append(encrypted_char)
    encrypted_str = ''.join(encrypted)
    return base64.urlsafe_b64encode(encrypted_str.encode()).decode()

def xor_decrypt(encrypted_text: str, passkey: str) -> str:
    """Simple XOR decryption"""
    try:
        encrypted_str = base64.urlsafe_b64decode(encrypted_text.encode()).decode()
        key = generate_key(passkey)
        decrypted = []
        for i, char in enumerate(encrypted_str):
            key_char = key[i % len(key)]
            decrypted_char = chr(ord(char) ^ key_char)
            decrypted.append(decrypted_char)
        return ''.join(decrypted)
    except:
        return None

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# Custom CSS with animations (unchanged)
st.markdown("""
    <style>
        body, .stApp {
            background-color: #0E1117;
            color: white;
            transition: all 0.3s ease;
        }
        .block-container {
            border: 1px solid #2E4053;
            padding: 2rem;
            border-radius: 10px;
            background-color: #1A1A1A;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .block-container:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.3);
        }
        textarea, input, .stButton>button, .stTextInput>div>input {
            background-color: #222 !important;
            color: white !important;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .stButton>button {
            border: 1px solid #4CAF50;
        }
        .stButton>button:hover {
            background-color: #45a049 !important;
            transform: scale(1.02);
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
def init_session():
    defaults = {
        'stored_data': {},
        'failed_attempts': 0,
        'authenticated': False
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session()

def show_unauthorized_message():
    with st.empty():
        st.warning("🔒 Authentication Required")
        time.sleep(0.5)
        st.warning("🔒 Verifying Credentials...")
        time.sleep(0.5)
        st.error("🚫 Access Denied - Please authenticate")
        time.sleep(1)

# UI Starts (unchanged except for encryption/decryption calls)
st.title("🔒 Secure Data Vault")

menu = ["Home", "Store Data", "Retrieve Data", "Authentication"]

with st.sidebar:
    st.markdown("## 🔐 Navigation Panel")
    choice = st.radio("Menu Options", menu)
    st.markdown("---")
    st.caption("Secure Data Management System")

# Authentication check
if not st.session_state.authenticated and choice != "Authentication":
    show_unauthorized_message()
    choice = "Authentication"  # Redirect to authentication

if choice == "Home":
    st.subheader("🏠 Vault Overview")
    st.markdown("""
    - 🔒 **Secure Storage**: Encrypt sensitive data
    - 🔑 **Passkey Protection**: Access your data only with the correct passkey
    - ⚠️ **Security Protocol**: System locks after 3 failed attempts
    """)
    st.markdown('<div class="fade-in">', unsafe_allow_html=True)
    st.caption("ℹ️ Data is stored in session memory and cleared when the session ends")
    st.markdown('</div>', unsafe_allow_html=True)

elif choice == "Store Data":
    st.subheader("📥 Store Encrypted Data")
    entry_name = st.text_input("Data Identifier (e.g., 'Email Credentials')")
    user_text = st.text_area("Data to Encrypt")
    user_passkey = st.text_input("Set Access Passphrase", type="password")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Secure Data", key="encrypt_btn"):
            if all([user_text, user_passkey, entry_name]):
                with st.spinner("🔐 Encrypting data..."):
                    time.sleep(0.5)  # Simulate processing
                    encrypted = xor_encrypt(user_text, user_passkey)
                    hashed_passkey = hash_passkey(user_passkey)
                    st.session_state.stored_data[entry_name] = {
                        "encrypted_text": encrypted,
                        "passkey": hashed_passkey,
                        "timestamp": str(datetime.datetime.now())
                    }
                    st.success("✅ Data secured successfully!")
                    st.code(encrypted, language="text")
            else:
                st.error("⚠️ Please complete all fields")
    with col2:
        if st.button("Reset Form", key="clear_btn"):
            st.session_state.clear()
            init_session()
            st.success("🔄 Form reset successfully")
            time.sleep(0.5)
            st.rerun()

elif choice == "Retrieve Data":
    st.subheader("📤 Retrieve Secured Data")
    
    if not st.session_state.stored_data:
        st.info("🔍 No encrypted data found in vault")
        st.stop()
    
    search_label = st.text_input("Search by Identifier")
    sorted_data = sorted(st.session_state.stored_data.items(), 
                       key=lambda x: x[1]['timestamp'], 
                       reverse=True)
    
    filtered_data = {k: v for k, v in sorted_data if search_label.lower() in k.lower()}

    if not filtered_data:
        st.warning("❌ No matching entries found")
        st.stop()

    selected_label = st.selectbox("Select Data Entry", list(filtered_data.keys()))
    key_input = st.text_input("Enter Access Passphrase", type="password")

    st.info(f"🔐 Attempts remaining: {MAX_ATTEMPTS - st.session_state.failed_attempts}")

    if st.button("Decrypt Data"):
        if not (selected_label and key_input):
            st.error("⚠️ Complete all fields to proceed")
            st.stop()
            
        with st.spinner("🔓 Decrypting..."):
            time.sleep(0.5)  # Simulate processing
            entry = filtered_data[selected_label]
            encrypted_text = entry["encrypted_text"]
            result = xor_decrypt(encrypted_text, key_input)
            
            if result:
                # Verify the passkey matches
                if hash_passkey(key_input) == entry['passkey']:
                    st.success("✅ Access granted - Decryption successful!")
                    st.code(result, language="text")
                    st.caption(f"🕒 Secured on: {entry['timestamp']}")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Invalid passphrase! Remaining attempts: {remaining}")
            else:
                st.session_state.failed_attempts += 1
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Invalid passphrase! Remaining attempts: {remaining}")
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🚨 Maximum attempts reached - System locked")
                    st.session_state.authenticated = False
                    time.sleep(1)
                    st.rerun()

    st.download_button(
        "Export Encrypted Data", 
        filtered_data[selected_label]["encrypted_text"],
        file_name=f"{selected_label}_encrypted.txt"
    )

    if st.button(f"Remove Entry: {selected_label}"):
        if st.checkbox("Confirm permanent deletion"):
            del st.session_state.stored_data[selected_label]
            st.success(f"🗑️ Entry '{selected_label}' permanently removed")
            time.sleep(0.5)
            st.rerun()

    if st.button("Backup Entire Vault"):
        data_json = json.dumps(st.session_state.stored_data, indent=2)
        st.download_button(
            "Download Encrypted Vault", 
            data_json, 
            file_name="secure_vault_backup.json"
        )

elif choice == "Authentication":
    st.subheader("🔑 System Authentication")
    
    if st.session_state.authenticated:
        st.success("✅ You are currently authenticated")
        if st.button("Terminate Session"):
            st.session_state.authenticated = False
            st.success("🔒 Session terminated successfully")
            time.sleep(0.5)
            st.rerun()
    else:
        master_key = st.text_input("Enter Administrator Credentials", type="password")
        
        if st.button("Authenticate"):
            if not master_key:
                st.error("🛑 Credentials required")
            elif master_key == MASTER_PASSWORD:
                with st.spinner("🔐 Verifying credentials..."):
                    time.sleep(0.5)  # Simulate authentication process
                    st.session_state.failed_attempts = 0
                    st.session_state.authenticated = True
                    st.success("✅ Authentication successful")
                    time.sleep(0.5)
                    st.rerun()
            else:
                st.error("❌ Invalid credentials - Access denied")
