#!/bin/bash

# Define file paths
PRIVATE_KEY_PATH="routes/private.pem"
PUBLIC_KEY_PATH="routes/public.pem"

# Check if both key files do not exist
if [ ! -f "$PRIVATE_KEY_PATH" ] && [ ! -f "$PUBLIC_KEY_PATH" ]; then
    echo "Key files not found. Generating keys..."
    python3 keygen.py
else
    echo "Key files already exist. Skipping key generation."
fi

# Start the uvicorn server
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload
