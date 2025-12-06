"""Unit tests for CVSS calculation module."""

import unittest
import sys
import os

# Add parent directory to path for lib imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.cvss import (
    calculate_cvss_v3_score,
    calculate_cvss_v2_score,
    get_severity_rating,
    get_severity_priority
)


class TestCVSSCalculations(unittest.TestCase):
    """Test CVSS score calculation functions."""
    
    def test_cvss_v3_calculation(self):
        """Test CVSS v3 score calculation with known vector."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = calculate_cvss_v3_score(vector)
        self.assertEqual(score, "9.8")
    
    def test_cvss_v3_invalid_vector(self):
        """Test CVSS v3 with invalid vector returns N/A."""
        score = calculate_cvss_v3_score("invalid")
        self.assertEqual(score, "N/A")
    
    def test_cvss_v2_calculation(self):
        """Test CVSS v2 score calculation with known vector."""
        vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        score = calculate_cvss_v2_score(vector)
        self.assertEqual(score, "7.5")
    
    def test_cvss_v2_invalid_vector(self):
        """Test CVSS v2 with invalid vector returns N/A."""
        score = calculate_cvss_v2_score("invalid")
        self.assertEqual(score, "N/A")
    
    def test_severity_rating_critical(self):
        """Test CRITICAL severity rating."""
        rating = get_severity_rating("9.5", "CVSS:3.1/...")
        self.assertEqual(rating, "CRITICAL")
    
    def test_severity_rating_high(self):
        """Test HIGH severity rating."""
        rating = get_severity_rating("7.5", "CVSS:3.1/...")
        self.assertEqual(rating, "HIGH")
    
    def test_severity_rating_medium(self):
        """Test MEDIUM severity rating."""
        rating = get_severity_rating("5.5", "CVSS:3.1/...")
        self.assertEqual(rating, "MEDIUM")
    
    def test_severity_rating_low(self):
        """Test LOW severity rating."""
        rating = get_severity_rating("2.5", "CVSS:3.1/...")
        self.assertEqual(rating, "LOW")
    
    def test_severity_rating_invalid(self):
        """Test invalid score returns UNKNOWN."""
        rating = get_severity_rating("invalid", "CVSS:3.1/...")
        self.assertEqual(rating, "UNKNOWN")
    
    def test_severity_priority_ordering(self):
        """Test severity priority values are correctly ordered."""
        self.assertLess(
            get_severity_priority("CRITICAL"),
            get_severity_priority("HIGH")
        )
        self.assertLess(
            get_severity_priority("HIGH"),
            get_severity_priority("MEDIUM")
        )
        self.assertLess(
            get_severity_priority("MEDIUM"),
            get_severity_priority("LOW")
        )


if __name__ == '__main__':
    unittest.main()
