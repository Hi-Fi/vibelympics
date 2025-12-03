import os
import subprocess
import sys

# Get the port from the environment, default to 8501
port = os.environ.get("PORT", "8501")

# Define the command to run Streamlit
cmd = [
    "/app/venv/bin/streamlit",
    "run",
    "app.py",
    "--server.port", port,
    "--server.address", "0.0.0.0"
]

# Run the command
# We use execvp to replace the current process with Streamlit
# This ensures Streamlit receives shutdown signals correctly
os.execvp(cmd[0], cmd)