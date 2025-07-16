# modules/reconnaissance/subdomain_scanner.py
import requests
from concurrent.futures import ThreadPoolExecutor
from core.utils.logger import CyberLogger

class SubdomainScanner:
    def __init__(self, domain, wordlist="resources/wordlists/subdomains.txt"):
        self.domain = domain
        self.wordlist = wordlist
        self.logger = CyberLogger()
        self.found = []
        
    def _load_wordlist(self):
        with open(self.wordlist) as f:
            return [line.strip() for line in f]
        
    def _check_subdomain(self, subdomain):
        url = f"http://{subdomain}.{self.domain}"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code < 400:
                self.found.append(url)
                self.logger.info(f"Discovered: {url}")
        except:
            pass
            
    def scan(self, threads=10):
        self.logger.info(f"Starting subdomain scan for {self.domain}")
        wordlist = self._load_wordlist()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self._check_subdomain, wordlist)
            
        return self.found