# tests/unit/reconnaissance/test_subdomain.py
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Mock the logger before importing SubdomainScanner
from core.utils import logger
logger.CyberLogger = MagicMock()

from modules.reconaissance.subdomain_scanner import SubdomainScanner

class TestSubdomainScanner:
    @pytest.fixture
    def scanner(self):
        return SubdomainScanner("example.com", "resources/wordlists/test_subdomains.txt")
        
    def test_wordlist_loading(self, scanner):
        assert len(scanner._load_wordlist()) > 0
        
    def test_scan_execution(self, scanner):
        results = scanner.scan(threads=1)
        assert isinstance(results, list)