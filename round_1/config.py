# Security Settings
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

# Content Security Policy
# Note: force_https is enabled by default in Talisman, it does not belong in this dict.
# We add 'unsafe-inline' because the app uses inline style attributes and event handlers (onclick).
CSP_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
}

# Image Processing Settings
EMOJI_GRADIENT = ["⬛", "💣", "🦍", "🎱", "🌑", "🌒", "🌓", "🌔", "🌕", "🏐", "🤍", "⬜"]
TARGET_WIDTH = 120 
BUCKET_SIZE = 255 / len(EMOJI_GRADIENT)
FRAMES = 12