# Demonstration of Secure Enclaves
Demonstrates how to use AWS Nitro secure enclaves. This code should be portable to any GPU as well.

# Structure
The secure enclave itself is housed within the AWS Nitro EC2 instance, with no access to the outside world. The only way to access it is via 
`AF_VSOCK` interface, used by both the `client.py` and the `server.py` instances. The secure enclave generates a private/public key pair and shares its public key with the client, whereas the client does the same and shares its public key with the enclave. When communicating with the client, the enclave encrypts messages using the client's public key, and the client decrypts the messages using its private key. The same process occurs when the client is communicating with the SE.

# Prerequisites
- Amazon Nitro Enclave EC2 instance.
- Docker. 
- Python.

# Instructions for use
1. Run `./build-enclave.sh` to start the enclave. 
2. Run `python3 client.py` to start the communications. 
3. Run `./terminate-enclave.sh` to clean up and start over.