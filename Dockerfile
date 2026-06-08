# Dockerfile for pulp-tool
# Base image: Fedora 45 (system python3 is 3.15)
FROM registry.fedoraproject.org/fedora:45@sha256:4cb651e59f9bdef53f826ffc8d8d84980d0d8dac17924dc2a2c735ab947cba05

RUN dnf install -y python3 python3-pip jq && dnf clean all

# Set working directory
WORKDIR /app

# Copy project files needed for installation
COPY setup.py pyproject.toml README.md MANIFEST.in VERSION ./
COPY pulp_tool/ ./pulp_tool/

# gcc is required at install time to build pydantic-core for Python 3.15
RUN dnf install -y gcc \
    && pip install --no-cache-dir . \
    && rm -rf /root/.cache \
    && dnf remove -y gcc \
    && dnf clean all

# The pulp-tool command is now available in PATH
# No entrypoint specified - users can run commands as needed
