# We keep the HTML separate to keep the main logic clean.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>🎨🤖</title>
    <style nonce="{{ csp_nonce() }}">
        /* --- CRT VIBE --- */
        body { 
            background-color: #050505; color: #ddd; 
            font-family: 'Courier New', monospace; 
            text-align: center; margin: 0; height: 100vh;
            display: flex; flex-direction: column; 
            align-items: center; justify-content: center; overflow: hidden; 
        }

        body::before {
            content: " "; display: block; position: absolute;
            top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), 
                        linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 100; background-size: 100% 2px, 3px 100%; pointer-events: none; 
        }

        .crt-wrapper {
            width: 100%; height: 100%;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            animation: flicker 0.15s infinite;
            text-shadow: 0 0 8px rgba(255, 255, 255, 0.4); 
        }

        @keyframes flicker {
            0% { opacity: 0.97; } 50% { opacity: 0.95; } 100% { opacity: 0.97; }
        }

        /* --- DROP ZONE --- */
        #drop-zone {
            border: 4px dashed #444; border-radius: 20px;
            width: 60%; max-width: 500px; padding: 60px 20px;
            cursor: default; user-select: none; position: relative;
            background-color: rgba(20, 20, 20, 0.5);
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            animation: breathe 3s infinite ease-in-out;
            min-height: 200px;
        }

        #drop-zone.hover {
            border-color: #fff; background-color: #222; transform: scale(1.05); animation: none;
        }

        .instruction-emojis { font-size: 6rem; display: flex; gap: 30px; align-items: center; }
        
        /* --- BUTTONS (Decision Mode) --- */
        .choice-container {
            display: flex; gap: 40px; margin-top: 20px;
        }
        .choice-btn {
            font-size: 4rem; cursor: pointer; border: 2px solid #444; 
            padding: 10px 20px; border-radius: 15px; background: #111;
            transition: all 0.2s;
        }
        .choice-btn:hover {
            transform: scale(1.1); border-color: #fff; background: #333;
        }

        /* --- CONTROLS --- */
        .controls-row {
            margin-bottom: 10px; display: flex; gap: 20px; font-size: 2rem; user-select: none; z-index: 10;
            align-items: center; justify-content: center;
        }
        .btn { 
            cursor: pointer; opacity: 0.6; padding: 5px 10px; border: 1px solid #333; border-radius: 8px; 
            background: #111; transition: all 0.1s;
        }
        .btn:hover { transform: scale(1.1); opacity: 1; border-color: #666; text-shadow: 0 0 10px white; }
        .btn:active { transform: scale(0.95); }

        /* --- CORNER FLAG --- */
        .corner-flag {
            position: fixed;
            bottom: 10px;
            right: 10px;
            font-size: 1.5rem; 
            opacity: 0.2;      
            z-index: 1000;
            cursor: pointer;   /* Changed to pointer to indicate interaction */
            transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); /* Smooth, bouncy expansion */
            animation: flag-float 4s ease-in-out infinite;
            filter: drop-shadow(0 0 5px rgba(255, 255, 255, 0.3));
        }

        /* Expanded State */
        .corner-flag.fullscreen {
            bottom: 0;
            right: 0;
            width: 100vw;
            height: 100vh;
            font-size: 50vh; /* Huge size */
            opacity: 1;
            background-color: rgba(0, 0, 0, 0.95); /* Dim background */
            display: flex;
            align-items: center;
            justify-content: center;
            animation: none; /* Stop floating */
            z-index: 9999;
        }

        @keyframes flag-float {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-3px) rotate(5deg); }
        }

        /* --- RESULT --- */
        pre { 
            font-size: 6px; line-height: 1.0; white-space: pre-wrap; word-break: break-all;
            text-align: center; overflow: hidden; max-width: 95vw; max-height: 80vh;
        }
    </style>
</head>
<body>
    
    <div class="crt-wrapper">
        <div id="drop-zone">
            <div class="instruction-emojis" id="instruction">
                <div>🖼️</div><div style="font-size: 3rem; opacity: 0.5;">➡️</div><div>📥</div>
            </div>
            
            <div id="choices" class="choice-container" style="display: none;">
                <div class="choice-btn" onclick="triggerSingle()" title="Single Image">⚡</div>
                <div class="choice-btn" onclick="triggerMorph()" title="Morph">➕</div>
            </div>
        </div>
        
        <div id="result-container" style="display:none;">
            <div class="controls-row">
                <div class="btn" onclick="zoom(-1)">➖</div>
                <div class="btn" onclick="zoom(1)">➕</div>
                <div class="btn" onclick="downloadArt()">💾</div>
                <div class="btn" onclick="window.location.reload()">🔄</div>
            </div>
            <div class="controls-row" id="speed-controls" style="display:none;">
                <div class="btn" onclick="changeSpeed(50)">🐢</div> 
                <div class="btn" onclick="changeSpeed(-50)">🐇</div> 
            </div>
            <pre id="art"></pre>
        </div>
    </div>

    <!-- The Corner Flag (Click to toggle fullscreen) -->
    <div class="corner-flag" onclick="this.classList.toggle('fullscreen')">🇫🇮</div>

    <script nonce="{{ csp_nonce() }}">
        const dropZone = document.getElementById('drop-zone');
        const instruction = document.getElementById('instruction');
        const choices = document.getElementById('choices');
        const resultContainer = document.getElementById('result-container');
        const speedControls = document.getElementById('speed-controls');
        const art = document.getElementById('art');

        let file1 = null;
        let mode = 'IDLE'; 

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => { e.preventDefault(); e.stopPropagation(); }, false);
        });

        dropZone.addEventListener('dragenter', () => {
            if (mode === 'DECISION') return;
            dropZone.classList.add('hover');
            instruction.innerHTML = '😲'; 
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('hover');
            resetInstruction();
        });

        function resetInstruction() {
            if (mode === 'IDLE') {
                instruction.innerHTML = '<div>🖼️</div><div style="font-size: 3rem; opacity: 0.5;">➡️</div><div>📥</div>';
            } else if (mode === 'WAITING_SECOND') {
                instruction.innerHTML = '<div>✅</div><div style="font-size: 3rem; opacity: 0.5;">➕</div><div>2️⃣</div>';
            }
        }

        dropZone.addEventListener('drop', (e) => {
            dropZone.classList.remove('hover');
            let dt = e.dataTransfer;
            let file = dt.files[0];

            if (mode === 'IDLE') {
                file1 = file;
                mode = 'DECISION';
                instruction.innerHTML = '✅';
                choices.style.display = 'flex';
            } else if (mode === 'WAITING_SECOND') {
                uploadFiles(file1, file);
            }
        });

        function triggerSingle() { uploadFiles(file1, null); }
        function triggerMorph() {
            mode = 'WAITING_SECOND';
            choices.style.display = 'none';
            resetInstruction();
        }

        function uploadFiles(f1, f2) {
            instruction.innerHTML = '⏳';
            choices.style.display = 'none';
            
            let formData = new FormData();
            formData.append('file1', f1);
            if (f2) formData.append('file2', f2);

            fetch('/process', { method: 'POST', body: formData })
            .then(response => {
                if (response.status === 413) throw new Error("File too large (Max 5MB)");
                if (response.status === 429) throw new Error("Too many requests (Slow down)");
                return response.json();
            })
            .then(data => {
                if (data.error) throw new Error(data.error);
                startAnimation(data.frames);
            })
            .catch(error => {
                instruction.innerHTML = '❌☠️';
                console.error(error);
            });
        }

        // --- Animation Logic ---
        let animationInterval;
        let frameIndex = 0;
        let currentSize = 6;
        let currentSpeed = 100;
        let currentFrames = [];

        function startAnimation(frames) {
            currentFrames = frames;
            dropZone.style.display = 'none';
            resultContainer.style.display = 'flex';
            resultContainer.style.flexDirection = 'column';
            resultContainer.style.alignItems = 'center';

            if (frames.length === 1) {
                art.textContent = frames[0];
            } else {
                speedControls.style.display = 'flex';
                runLoop();
            }
        }

        function runLoop() {
            if (animationInterval) clearInterval(animationInterval);
            animationInterval = setInterval(() => {
                art.textContent = currentFrames[frameIndex];
                frameIndex = (frameIndex + 1) % currentFrames.length;
            }, currentSpeed);
        }

        function changeSpeed(delta) {
            currentSpeed += delta;
            if (currentSpeed < 20) currentSpeed = 20;
            if (currentSpeed > 500) currentSpeed = 500;
            runLoop();
        }

        function zoom(direction) {
            currentSize += direction;
            if (currentSize < 1) currentSize = 1;
            if (currentSize > 50) currentSize = 50;
            art.style.fontSize = currentSize + 'px';
        }

        function downloadArt() {
            const text = art.textContent;
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'emoji-art.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    </script>
</body>
</html>
"""