#/bin/bash

sudo docker build -t simple-enclave-image .
sudo nitro-cli build-enclave --docker-uri simple-enclave-image --output-file simple-enclave.eif
sudo nitro-cli run-enclave --eif-path simple-enclave.eif --memory 3060 --cpu-count 2 --debug-mode