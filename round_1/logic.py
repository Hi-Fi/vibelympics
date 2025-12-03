import io
from PIL import Image
from config import EMOJI_GRADIENT, TARGET_WIDTH, BUCKET_SIZE, FRAMES

def image_to_emojis(img):
    """Converts a single PIL image to an ASCII-style emoji string."""
    pixels = img.getdata()
    emoji_string = ""
    for pixel_val in pixels:
        index = int(pixel_val / BUCKET_SIZE)
        index = min(max(index, 0), len(EMOJI_GRADIENT) - 1)
        emoji_string += EMOJI_GRADIENT[index]
    
    output = ""
    for i in range(0, len(emoji_string), TARGET_WIDTH):
        output += emoji_string[i:i + TARGET_WIDTH] + "\n"
    return output

def process_request(file1_bytes, file2_bytes=None):
    """
    Handles the processing logic. 
    If file2 is provided, generates a morph animation.
    If not, generates a single static image.
    """
    try:
        img1 = Image.open(io.BytesIO(file1_bytes))
        width, height = img1.size
        ratio = height / width / 0.95
        new_height = int(TARGET_WIDTH * ratio)
        
        # Resize Image 1
        img1 = img1.resize((TARGET_WIDTH, new_height)).convert("L")
        
        frames = []

        if file2_bytes:
            # --- MORPH MODE ---
            img2 = Image.open(io.BytesIO(file2_bytes))
            img2 = img2.resize((TARGET_WIDTH, new_height)).convert("L")
            
            # Generate Blend Frames
            for i in range(FRAMES + 1):
                alpha = i / FRAMES
                blended = Image.blend(img1, img2, alpha)
                frames.append(image_to_emojis(blended))
            
            # Add ping-pong loop (reverse back to start)
            frames += frames[-2:0:-1]
            
        else:
            # --- SINGLE MODE ---
            frames.append(image_to_emojis(img1))
            
        return frames
    except Exception as e:
        print(f"Error in processing: {e}")
        return None