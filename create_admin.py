import argparse
import getpass
import json
import os
import sys

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import auth, credentials


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Create a Firebase user for testing and grant the admin claim."
    )
    parser.add_argument("--email", help="Email address for the admin account")
    args = parser.parse_args()

    email = args.email or input("Admin email: ").strip()
    if not email:
        parser.error("An email address is required.")

    credentials_json = os.getenv("FIREBASE_CREDENTIALS")
    if not credentials_json:
        parser.error("FIREBASE_CREDENTIALS is missing from the environment.")

    try:
        service_account = json.loads(credentials_json)
    except json.JSONDecodeError as error:
        parser.error(f"FIREBASE_CREDENTIALS is not valid JSON: {error}")

    database_url = os.getenv("FIREBASE_DATABASE_URL")
    options = {"databaseURL": database_url} if database_url else None
    firebase_admin.initialize_app(
        credentials.Certificate(service_account),
        options=options,
    )

    try:
        user = auth.get_user_by_email(email)
        print("Existing Firebase account found; its password will not be changed.")
    except auth.UserNotFoundError:
        password = getpass.getpass("New account password (at least 6 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if len(password) < 6:
            parser.error("Firebase passwords must contain at least 6 characters.")
        if password != confirmation:
            parser.error("Passwords do not match.")
        user = auth.create_user(email=email, password=password)
        print("Created Firebase account.")

    claims = dict(user.custom_claims or {})
    claims["admin"] = True
    claims["role"] = "admin"
    auth.set_custom_user_claims(user.uid, claims)
    print(f"Granted admin claim to {user.email}.")
    print("The user may need to sign in again to receive the updated claim.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except firebase_admin.exceptions.FirebaseError as error:
        print(f"Firebase operation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
