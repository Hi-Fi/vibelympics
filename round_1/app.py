from flask import Flask, request, render_template_string, jsonify
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import CSP_POLICY, MAX_UPLOAD_SIZE
from logic import process_request
from ui import HTML_TEMPLATE

app = Flask(__name__)

# --- Security Setup ---
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE

talisman = Talisman(app, content_security_policy=CSP_POLICY)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --- Routes ---

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/process", methods=["POST"])
@limiter.limit("5 per minute")
def process():
    if 'file1' not in request.files:
        return jsonify({"error": "Missing file"})
    
    file2 = None
    if 'file2' in request.files and request.files['file2'].filename != '':
        file2 = request.files['file2'].read()

    # Process without dynamic user flags
    frames = process_request(request.files['file1'].read(), file2)
    
    if not frames:
        return jsonify({"error": "Processing failed"})
        
    return jsonify({"frames": frames})