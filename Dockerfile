# Use Amazon Linux 2 as the base image
FROM amazonlinux:2

# Install necessary tools and libraries
RUN yum install -y gcc python3 python3-devel && \
    pip3 install --no-cache-dir cryptography

# Copy your Python script into the container
COPY server.py /server.py

# Set the working directory
WORKDIR /

# Ensure the script is executable
RUN chmod +x /server.py

EXPOSE 5000

# Run the application as root
CMD ["python3", "/server.py"]
