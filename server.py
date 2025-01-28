import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import socket

# Ensure the /tmp directory exists
os.makedirs("/tmp", exist_ok=True)

# Generate the RSA Key Pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Paths to store keys
PRIVATE_KEY_PATH = "/tmp/enclave_private_key.pem"
PUBLIC_KEY_PATH = "/tmp/enclave_public_key.pem"

# Serialize the Private Key
with open(PRIVATE_KEY_PATH, "wb") as private_file:
    private_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
print("Enclave private key successfully written.")

# Serialize the Public Key
with open(PUBLIC_KEY_PATH, "wb") as public_file:
    public_file.write(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
print("Enclave public key successfully written.")

# Start the vsock Server
VSOCK_PORT = 5000
try:
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as server:
        server.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
        server.listen()
        print(f"Enclave listening on vsock port {VSOCK_PORT}")

        conn, _ = server.accept()
        print("Connection accepted. Sending public key to client...")

        with conn:
            # Send the enclave's public key to the client
            with open(PUBLIC_KEY_PATH, "rb") as public_file:
                enclave_public_key = public_file.read()
            conn.sendall(enclave_public_key)
            print("Enclave public key sent.")

            # Receive the client's public key
            client_public_key = conn.recv(4096)
            print("Client public key received.")

            # Load the client's public key
            loaded_client_public_key = serialization.load_pem_public_key(client_public_key)

            # Receive the encrypted message from the client
            encrypted_message = conn.recv(4096)
            print("Encrypted message received from client.")

            # Load the enclave's private key
            with open(PRIVATE_KEY_PATH, "rb") as private_file:
                enclave_private_key = serialization.load_pem_private_key(
                    private_file.read(),
                    password=None,
                    backend=default_backend()
                )

            # Decrypt the message using the enclave's private key
            decrypted_message = enclave_private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Decrypted message from client: {decrypted_message.decode()}")

            # Encrypt a response using the client's public key
            response_message = b"Hello from the enclave!"
            encrypted_response = loaded_client_public_key.encrypt(
                response_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.sendall(encrypted_response)
            print("Encrypted response sent to client.")

except Exception as e:
    print(f"Failed to start vsock server: {e}")
