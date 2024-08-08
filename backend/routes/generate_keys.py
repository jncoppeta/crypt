from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key_pair():
    """Generate a new RSA key pair."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    return private_key, public_key

def save_keys_to_files(private_key, public_key, private_key_file, public_key_file):
    """Save the private and public keys to PEM files."""
    # Save private key
    with open(private_key_file, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save public key
    with open(public_key_file, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Generate RSA key pair
private_key, public_key = generate_key_pair()

# Save keys to files
save_keys_to_files(private_key, public_key, "private.pem", "public.pem")

print("Keys have been generated and saved to 'private.pem' and 'public.pem'")
