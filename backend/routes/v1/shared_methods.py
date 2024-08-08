import uuid
from fastapi import HTTPException
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64
from dotenv import load_dotenv
import os
import random
import string

load_dotenv()
INIT_TOKEN = os.getenv("INIT_TOKEN")

def is_admin_token(authorization):
    with open('routes/admin_token.txt', 'r') as f:
        ADMIN_TOKEN = f.read()
    if authorization.split(' ')[0] == ADMIN_TOKEN:
        return True
    else:
        return False

def check_auth_admin(authorization: str, route: str):
    """Checks the bearer token to make sure it is the admin token."""
    try:
        with open('routes/admin_token.txt', 'r') as f:
            ADMIN_TOKEN = f.read()
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        
        token_value = authorization.split(' ')[1]
        if token_value == INIT_TOKEN:
            print(f"Authorized(INIT): {route}")
            return
        else:
            print(f"token_value: {token_value}")
            print(f"ADMIN_TOKEN: {ADMIN_TOKEN}")
        if token_value == get_decrypted(ADMIN_TOKEN):
            print(f"Authorized(ADMIN): {route}")
            return
        else:
            print(f"Unauthorized: {route}")
            raise HTTPException(status_code=401, detail="Unauthorized")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

def generate_uuid():

    """Generates a random UUID for the token ID."""
    return uuid.uuid4()

def generate_token():
    """Generate a random string of given length with digits, lowercase and uppercase letters."""
    characters = string.ascii_letters + string.digits  # Combine letters and digits
    return ''.join(random.choice(characters) for _ in range(32))

def check_auth(authorization: str, db: Session, route: str):
    from routes.v1.tokens import find_token_by_value
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")

        token = find_token_by_value(db, authorization)

        if token:
            print(f">> Authorization confirmed: {route}")
        else:
            raise HTTPException(status_code=401, detail="Invalid token")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def load_public_key() -> rsa.RSAPublicKey:
    """Load and return the public key from the PEM file."""
    with open("routes/public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_private_key(password: bytes = None) -> rsa.RSAPrivateKey:
    """Load and return the private key from the PEM file.

    Args:
        password (bytes): The password to decrypt the private key, if encrypted.

    Returns:
        rsa.RSAPrivateKey: The loaded private key.
    """
    with open("routes/private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password
        )
    return private_key

def encrypt(message: str, public_key: rsa.RSAPublicKey) -> str:
    """Encrypt a message using the provided public key.
    
    Args:
        message (str): The plaintext message to encrypt.
        public_key (rsa.RSAPublicKey): The RSA public key for encryption.
    
    Returns:
        str: The base64-encoded encrypted message.
    """
    print(type(public_key))
    encrypted_data = public_key.encrypt(
        message.encode('utf-8'),    
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt(ciphertext: str, private_key: rsa.RSAPrivateKey) -> str:
    """Decrypt a ciphertext using the provided private key.
    
    Args:
        ciphertext (str): The base64-encoded encrypted message.
        private_key (rsa.RSAPrivateKey): The RSA private key for decryption.
    
    Returns:
        str: The decrypted plaintext message.
    """
    encrypted_data = base64.b64decode(ciphertext)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')

def get_encrypted(username):
    return encrypt(username, load_public_key())

def get_decrypted(ciphertext):
    return decrypt(ciphertext, load_private_key())