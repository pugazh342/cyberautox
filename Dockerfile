# Dockerfile for CyberAutoX

# Use an official Python runtime as a parent image
# python:3.9-slim-buster provides a small, stable base on Debian Buster
FROM python:3.9-slim-bullseye

# Set environment variables to prevent Python from writing .pyc files
# and to buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies, including nmap and build tools
# build-essential, libssl-dev, libffi-dev are needed for some Python packages like cryptography
# curl and git are for downloading external tools
# libsasl2-dev, libldap2-dev are for ldap3 library (Active Directory module)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        git \
        curl \
        build-essential \
        libssl-dev \
        libffi-dev \
        libsasl2-dev \
        libldap2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install sqlmap (required by vulnerability_scanning module)
# Clone sqlmap repository directly into the container
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /usr/local/bin/sqlmap-master \
    && chmod +x /usr/local/bin/sqlmap-master/sqlmap.py \
    && ln -s /usr/local/bin/sqlmap-master/sqlmap.py /usr/local/bin/sqlmap

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire CyberAutoX project into the container's /app directory
COPY . /app

# Expose any ports that might be useful for future network services (optional for now)
# EXPOSE 8000

# Set the entrypoint to your CLI script
# This makes it so you can run 'docker run cyberautox vulnscan --target ...'
ENTRYPOINT ["python", "cyberautox.py"]

# Default command if no arguments are provided (e.g., just 'docker run cyberautox')
CMD ["--help"]