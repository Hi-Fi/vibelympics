# Security Settings
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

# Content Security Policy
CSP_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
}

# Image Processing Settings
# Fixed gradient including the Finnish flag 🇫🇮
EMOJI_GRADIENT = ["⬛", "💣", "🦍", "🎱", "🌑", "🌒", "🌓", "🌔", "🌕", "🏐", "🇫🇮", "🤍", "⬜"]

TARGET_WIDTH = 120 
BUCKET_SIZE = 255 / len(EMOJI_GRADIENT)
FRAMES = 12