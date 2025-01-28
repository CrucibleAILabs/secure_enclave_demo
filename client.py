import os
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Server details
ENCLAVE_CID = 58
ENCLAVE_PORT = 5000

# Ensure the /tmp directory exists
os.makedirs("/tmp", exist_ok=True)

# Generate the RSA Key Pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Paths to store keys
PRIVATE_KEY_PATH = "/tmp/client_private_key.pem"
PUBLIC_KEY_PATH = "/tmp/client_public_key.pem"

# Serialize the Private Key
with open(PRIVATE_KEY_PATH, "wb") as private_file:
    private_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
print("Client private key successfully written.")

# Serialize the Public Key
with open(PUBLIC_KEY_PATH, "wb") as public_file:
    public_file.write(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
print("Client public key successfully written.")

# Connect to the server
print(f"Connecting to server at CID {ENCLAVE_CID}:{ENCLAVE_PORT}...")
with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as client:
    client.connect((ENCLAVE_CID, ENCLAVE_PORT))
    print(f"Connected to enclave at CID {ENCLAVE_CID}:{ENCLAVE_PORT}")

    # Receive the enclave's public key
    enclave_public_key = client.recv(4096)
    print("Enclave public key received.")

    # Load the enclave's public key
    loaded_enclave_public_key = serialization.load_pem_public_key(enclave_public_key)

    # Send the client's public key to the enclave
    with open(PUBLIC_KEY_PATH, "rb") as public_file:
        client_public_key = public_file.read()
    client.sendall(client_public_key)
    print("Client public key sent to enclave.")

    # Encrypt a message using the enclave's public key
    message = b"Hello from the client!"
    encrypted_message = loaded_enclave_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client.sendall(encrypted_message)
    print("Encrypted message sent to enclave.")

    # Receive the encrypted response from the enclave
    encrypted_response = client.recv(4096)
    print("Encrypted response received from enclave.")

    # Load the client's private key
    with open(PRIVATE_KEY_PATH, "rb") as private_file:
        client_private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )

    # Decrypt the response using the client's private key
    decrypted_response = client_private_key.decrypt(
        encrypted_response,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Decrypted response from enclave: {decrypted_response.decode()}")
