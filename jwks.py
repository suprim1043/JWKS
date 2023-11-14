import os
import time
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

# Defining Constants
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
KEY_EXPIRY_DAYS = 30
SECRET_KEY = "your-secret-key"

# Check if keys exist, otherwise generate them
if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open(PRIVATE_KEY_FILE, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    public_key = private_key.public_key()

    with open(PUBLIC_KEY_FILE, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)



with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  #Keys are not encryptd
            backend=default_backend()
        )


#public key loaded
with open(PUBLIC_KEY_FILE, "rb") as public_key_file:
    public_key_data = public_key_file.read()
    public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())

#JWKS entry created
kid = "my-key-id"
expiry = datetime.utcnow() + timedelta(days=KEY_EXPIRY_DAYS)
jwks_entry = {
    "kid": kid,
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": public_key.public_numbers().n,
    "e": public_key.public_numbers().e,
    "exp": int(expiry.timestamp())
}

# User data for authentication
users = {"userABC": "password123"}

# Defining JWKS endpoint
@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify(keys=[jwks_entry])

# Defining authentication endpoint
#Used ChatGpt for this, payload involves "+" for authientication while expired key involves a "-"
@app.route("/auth", methods=["POST"])
def authenticate():
    global private_key 
    username = request.json.get("username")
    password = request.json.get("password")

    # Authenticaiton
    if username in users and users[username] == password:
        # Generate a JWT with the current key
        payload = {"sub": username, "exp": int((datetime.utcnow() + timedelta(days=1)).timestamp())}
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
        return jsonify({"token": token})
    else:
        return "Unauthorized", 401

# Define the endpoint to issue JWTs with an expired key
@app.route("/auth/expired", methods=["POST"])
def authenticate_expired():
    global private_key
    username = request.json.get("username")
    password = request.json.get("password")
    

    # Authentication
    if username in users and users[username] == password:
        # Generate a JWT with the expired key
        payload = {"sub": username, "exp": int((datetime.utcnow() - timedelta(days=1)).timestamp())}
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
        return jsonify({"token": token})
        

    else:
        return "Unauthorized", 401

#Running on port 8080
if __name__ == "__main__":
    app.run(port=8080)
