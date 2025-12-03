import unittest
import io
from PIL import Image
from app import app
import config
import logic

class TestConfiguration(unittest.TestCase):
    def test_security_settings(self):
        """Ensure security constants are set correctly."""
        self.assertEqual(config.MAX_UPLOAD_SIZE, 5 * 1024 * 1024)
        self.assertIn('default-src', config.CSP_POLICY)
        self.assertIn("'self'", config.CSP_POLICY['script-src'])
        # Check for force_https key presence or default behavior logic if needed
        # Since we removed it from dict, we rely on Talisman default or param

    def test_visual_settings(self):
        """Ensure visual configuration is valid."""
        self.assertTrue(len(config.EMOJI_GRADIENT) > 0)
        self.assertIsInstance(config.TARGET_WIDTH, int)
        self.assertGreater(config.TARGET_WIDTH, 0)
        expected_bucket = 255 / len(config.EMOJI_GRADIENT)
        self.assertAlmostEqual(config.BUCKET_SIZE, expected_bucket)

class TestLogic(unittest.TestCase):
    def create_dummy_image(self, color=0):
        """Helper to create a 10x10 single-color image in memory."""
        img = Image.new('L', (10, 10), color=color)
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()

    def test_image_to_emojis_dark(self):
        """Test that a black image maps to the darkest emoji."""
        img_bytes = self.create_dummy_image(color=0)
        result = logic.process_request(img_bytes)
        self.assertEqual(len(result), 1)
        darkest_emoji = config.EMOJI_GRADIENT[0]
        self.assertIn(darkest_emoji, result[0])

    def test_image_to_emojis_light(self):
        """Test that a white image maps to the lightest emoji."""
        img_bytes = self.create_dummy_image(color=255)
        result = logic.process_request(img_bytes)
        lightest_emoji = config.EMOJI_GRADIENT[-1]
        self.assertIn(lightest_emoji, result[0])

class TestAppRoutes(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_homepage(self):
        """Ensure the homepage loads successfully."""
        # FIX: Use base_url='https://...' to simulate HTTPS and avoid 302 Redirects
        response = self.client.get('/', base_url='https://localhost')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'nonce=', response.data)

    def test_process_no_file(self):
        """Ensure the /process endpoint handles missing files gracefully."""
        # FIX: Use base_url='https://...' to simulate HTTPS
        response = self.client.post('/process', base_url='https://localhost')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Missing file', response.data)

if __name__ == '__main__':
    unittest.main()