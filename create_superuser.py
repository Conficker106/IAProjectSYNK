import os
import re
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from dotenv import load_dotenv

# 1. Setup Environment
load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
# We don't need a secret key for a CLI script, but good practice to have env loaded
app.secret_key = os.urandom(24)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)


# 2. Helper: Same Password Validation as Main App
def is_password_strong(password):
    """
    Enforces: At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char.
    """
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)


def create_admin():
    print("\n" + "=" * 50)
    print("🔒 HEALTHCARE SYSTEM: SUPER ADMIN CREATION")
    print("=" * 50)

    # 3. Inputs
    username = input("Enter Admin Username: ").strip()
    email_input = input("Enter Admin Email: ").strip()
    password = input("Enter Admin Password: ").strip()

    # 4. Normalization (Critical for Email)
    email_final = email_input.lower()

    with app.app_context():
        # 5. Validation: Password Strength
        if not is_password_strong(password):
            print("\n❌ Error: Password is too weak.")
            print("   - Must be at least 8 characters")
            print("   - Must contain Uppercase, Lowercase, Number, and Special Char (@$!%*?&)")
            return

        # 6. Validation: Check for Duplicate Email (Case-Insensitive Regex)
        # matches logic in app.py
        existing_email = mongo.db.users.find_one({
            "email": {"$regex": f"^{re.escape(email_final)}$", "$options": "i"}
        })

        if existing_email:
            print(f"\n❌ Error: The email '{email_input}' is already registered.")
            return

        # 7. Validation: Check for Duplicate Username
        if mongo.db.users.find_one({"username": username}):
            print(f"\n❌ Error: The username '{username}' is already taken.")
            return

        # 8. Hashing & Creation
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        mongo.db.users.insert_one({
            'username': username,
            'email': email_final,  # Saved as lowercase
            'password': hashed_pw,
            'role': 'admin',  # Hardcoded as Admin
            'failed_attempts': 0,
            'locked_until': None,
            'token_version': 0  # Important for session management
        })

        print("\n" + "-" * 50)
        print(f"✅ SUCCESS! User '{username}' created with ADMIN privileges.")
        print(f"📧 Login Email: {email_final}")
        print("-" * 50)
        print("You can now launch 'app.py' and log in to create other staff members.")
        print("=" * 50 + "\n")


if __name__ == "__main__":
    create_admin()