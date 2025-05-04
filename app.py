import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# --- Session State Initialization ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True
if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = None

# --- Fernet Key (persistent) ---
KEY_FILE = "fernet.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
else:
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()

cipher = Fernet(key)

# --- Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def reset_failed_attempts():
    st.session_state.failed_attempts = 0
    st.session_state.lockout_until = None

def require_login():
    st.session_state.authorized = False

def authorize():
    st.session_state.authorized = True
    reset_failed_attempts()

def is_locked_out():
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        return True
    return False

def apply_lockout():
    st.session_state.lockout_until = datetime.now() + timedelta(minutes=5)

def save_data():
    try:
        with open("encrypted_data.json", "w") as f:
            json.dump(st.session_state.stored_data, f)
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

def load_data():
    try:
        if os.path.exists("encrypted_data.json"):
            with open("encrypted_data.json", "r") as f:
                st.session_state.stored_data = json.load(f)
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
        st.session_state.stored_data = {}

# Load data on startup
load_data()

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

# --- Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
if not st.session_state.authorized or is_locked_out():
    menu = ["Login"]  # Force login if not authorized or locked out
choice = st.sidebar.selectbox("Navigation", menu)

# --- Login Page ---
if choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if is_locked_out():
        remaining_time = st.session_state.lockout_until - datetime.now()
        st.error(f"❌ Account locked! Please try again in {int(remaining_time.total_seconds() / 60)} minutes.")
    else:
        username = st.text_input("Username", value="", key="login_user")
        password = st.text_input("Password", type="password", value="", key="login_pass")
        
        if st.button("Login"):
            # Simple check: username and password not empty
            if username and password:
                authorize()
                st.success("✅ Reauthorized! Please proceed.")
            else:
                st.error("❌ Both fields are required!")

# --- Home Page ---
elif choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    if st.session_state.failed_attempts > 0:
        st.warning(f"⚠️ You have {3 - st.session_state.failed_attempts} attempts remaining before lockout.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            try:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                st.session_state.stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "timestamp": datetime.now().isoformat()
                }
                save_data()  # Save to file
                st.success("✅ Data stored securely!")
            except Exception as e:
                st.error(f"Error encrypting data: {str(e)}")
        else:
            st.error("⚠️ Both fields are required!")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if is_locked_out():
        remaining_time = st.session_state.lockout_until - datetime.now()
        st.error(f"❌ Account locked! Please try again in {int(remaining_time.total_seconds() / 60)} minutes.")
    else:
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                try:
                    hashed_passkey = hash_passkey(passkey)
                    entry = st.session_state.stored_data.get(encrypted_text)
                    
                    if entry and entry["passkey"] == hashed_passkey:
                        decrypted_text = decrypt_data(encrypted_text)
                        st.success(f"✅ Decrypted Data: {decrypted_text}")
                        reset_failed_attempts()
                    else:
                        st.session_state.failed_attempts += 1
                        attempts_left = 3 - st.session_state.failed_attempts
                        
                        if attempts_left > 0:
                            st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                        else:
                            st.error("❌ Too many failed attempts! Account locked for 5 minutes.")
                            apply_lockout()
                            require_login()
                except Exception as e:
                    st.error(f"Error decrypting data: {str(e)}")
            else:
                st.error("⚠️ Both fields are required!") 