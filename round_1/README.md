# 🎨🤖 Emoji Art Generator

A secure, retro-futuristic web application that converts images into high-resolution emoji art. It runs in a hardened Docker container with full HTTPS encryption.

## ✨ Features

* **Zero-Text UI:** The entire interface uses emojis for a universal, immersive experience.
* **Dual Modes:**
  * **⚡ Single Mode:** Instantly convert one image into ASCII-style emoji art.
  * **➕ Morph Mode:** Drop two images to create a smooth, animated transformation between them.
* **Secure & Hardened:** Built on **Chainguard** (Wolfi OS) images with no shell access, running as a non-root user.
* **Encrypted:** Uses a self-signed SSL certificate to encrypt all traffic (HTTPS).
* **CRT Vibe:** The UI mimics an old-school terminal with scanlines, flicker, and phosphor glow.

## 🚀 Installation & Running (Docker)

### Prerequisites

You only need **Docker** installed on your machine.

### 1. Setup Files

Ensure you have the following files in a folder named `emoji-app`:

1. `app.py` (The Flask Application)
2. `config.py` (Configuration & Security Settings)
3. `logic.py` (Image Processing Logic)
4. `ui.py` (HTML/JS Frontend)
5. `Dockerfile` (The Secure Build Instructions)
6. `docker-compose.yml` (The Runner Config)
7. `requirements.txt` (Dependencies)

### 2. Build & Run

Open your terminal in the folder and run:

```bash
docker-compose up --build
```

This command will:

1. Download the secure Wolfi OS base image.
2. Compile the necessary image libraries.
3. Run the security unit tests.
4. Generate a unique SSL security certificate.
5. Start the Gunicorn server on port 8080.

### 3. Access the App

Open your browser and go to:

👉 https://localhost:8080

> **⚠️ Important:** Because we generate a self-signed security certificate inside the container, your browser will warn you that the connection is "Not Private". This is normal for local secure apps.
>
> **Click "Advanced" -> "Proceed to localhost (unsafe)" to continue.**

## 🐍 Local Development (No Docker)

If you prefer to run the app directly on your machine (Python 3.11+ required):

1. **Create a Virtual Environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install Dependencies:**

```bash
pip install -r requirements.txt
```

3. **Generate SSL Certificates:**
   The app enforces HTTPS. You must generate self-signed keys in the project folder:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=US/ST=Dev/L=Home/O=EmojiApp/CN=localhost"
```
4. **Run with Gunicorn:**
```bash
gunicorn --bind 0.0.0.0:8080 --certfile cert.pem --keyfile key.pem --workers 2 app:app
```
5. **Run Tests:**
```bash
python tests.py
```

## 🕹️ How to Use

The interface is entirely drag-and-drop. No clicking required!

### ⚡ Single Image Mode

1. **Drag & Drop** your image onto the `📥` box.
2. The box will show a checkmark `✅` and two buttons.
3. Click the **Lightning Bolt** `⚡` button.
4. Wait for the hourglass `⏳` to finish.
5. **Result:** Your static emoji art appears!

### ➕ Morph Mode (Animation)

1. **Drag & Drop** your **first** image (Image A) onto the box.
2. Click the **Plus** `➕` button.
3. The box will ask for the second image `2️⃣`.
4. **Drag & Drop** your **second** image (Image B).
5. **Result:** An animation loop morphing Image A into Image B will start.

### 🎛️ Controls

Once the art is generated, use the control bar at the top:

| Button | Function | 
| :--- | :--- | 
| `➖` | **Zoom Out:** Make the emoji pixels smaller (sharper image). | 
| `➕` | **Zoom In:** Make the emoji pixels larger (more abstract). | 
| `💾` | **Save:** Download the current art (or animation frame) as a text file. | 
| `🐢` | **Slower:** Decrease animation speed (Morph mode only). | 
| `🐇` | **Faster:** Increase animation speed (Morph mode only). | 
| `🔄` | **Reset:** Clear everything and start over. | 

## 🛠️ Technical Details for Nerds

* **Base Image:** `cgr.dev/chainguard/python:latest` (Wolfi OS)
* **Server:** Gunicorn with 2 workers.
* **Security:**
  * Runs as non-root user (`uid: 65532`).
  * Filesystem is read-only (mostly).
  * No shell (`/bin/sh` or `/bin/bash`) available inside the container.
* **SSL:** `openssl` generates a 4096-bit RSA key during the build stage.

## 🛑 Stopping the App

Press `Ctrl+C` in your terminal to stop the container. To remove it completely:
```bash
docker-compose down
```