from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3


# Create/open the SQLite database file
db_connection = sqlite3.connect('totally_not_my_privateKeys.db')

# Create the keys table if it doesn't exist
cursor = db_connection.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    exp INTEGER NOT NULL
)
''')
db_connection.commit()


hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


# Serialize the private key to PEM format
key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Save the private key to the database
cursor.execute('''
INSERT INTO keys (key, exp) VALUES (?, ?)
''', (key_pem.decode('utf-8'), int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))) #time right now and after 1 hour
db_connection.commit()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return


       

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                # Read an expired key from the database
                cursor.execute('SELECT key FROM keys WHERE exp < ?', (int(datetime.datetime.utcnow().timestamp()),))
            else:
                # Read a valid (unexpired) key from the database
                cursor.execute('SELECT key FROM keys WHERE exp >= ?', (int(datetime.datetime.utcnow().timestamp()),))

            key_pem = cursor.fetchone()[0]
            encoded_jwt = jwt.encode(
                {"user": "username", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                key_pem,
                algorithm="RS256",
                headers=headers
            )

            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded_jwt.encode("utf-8"))
            return
        else:
            self.send_response(405)
            self.end_headers()
            return


       





    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            cursor.execute('SELECT key FROM keys WHERE exp >= ?', (int(datetime.datetime.utcnow().timestamp()),))
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            for row in cursor.fetchall():
                key_pem = row[0]
                key = serialization.load_pem_private_key(key_pem.encode('utf-8'), password=None)
                key_n = key.private_numbers().public_numbers.n
                key_e = key.private_numbers().public_numbers.e
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "generatedKID",  # Replace with a unique key ID
                    "n": int_to_base64(key_n),
                    "e": int_to_base64(key_e),
                })
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    db_connection.close() #database connection closed
