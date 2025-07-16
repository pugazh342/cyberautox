# core/engines/web_crawler.py
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from core.utils.logger import CyberLogger

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = self._normalize_url(base_url)
        self.logger = CyberLogger()
        self.visited_urls = set()
        self.urls_to_visit = deque([self.base_url])
        self.discovered_urls = set() # To store all unique URLs found
        self.internal_links = set()  # Links within the same domain
        self.external_links = set()  # Links outside the domain

    def _normalize_url(self, url):
        """Ensures URL has a scheme and a trailing slash if it's a base path."""
        if not urlparse(url).scheme:
            url = "http://" + url # Default to HTTP if no scheme
        # Ensure trailing slash for consistent base paths, but not for files
        if url.endswith('/') or '.' in urlparse(url).path.split('/')[-1]: # If it's a directory or a file
             return url
        return url + '/'

    def _is_same_domain(self, url):
        """Checks if a URL belongs to the same domain as the base URL."""
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def crawl(self, max_depth=2, max_urls=100):
        """
        Starts the web crawling process.
        :param max_depth: Maximum depth to crawl.
        :param max_urls: Maximum number of unique URLs to visit.
        """
        self.logger.info(f"Starting web crawl from {self.base_url} (Max Depth: {max_depth}, Max URLs: {max_urls})")
        current_depth = 0

        while self.urls_to_visit and len(self.visited_urls) < max_urls and current_depth <= max_depth:
            current_url = self.urls_to_visit.popleft()

            if current_url in self.visited_urls:
                continue

            self.logger.info(f"Visiting: {current_url} (Depth: {current_depth})")
            self.visited_urls.add(current_url)
            self.discovered_urls.add(current_url)

            try:
                response = requests.get(current_url, timeout=5)
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

                # Basic HTML parsing (we'll expand this with BeautifulSoup later)
                # For now, just look for href attributes
                from bs4 import BeautifulSoup # Temporarily import here, will add to requirements

                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)
                    parsed_link = urlparse(absolute_url)
                    # Clean up URL (remove fragments, query params for uniqueness if desired)
                    clean_url = parsed_link.scheme + "://" + parsed_link.netloc + parsed_link.path

                    if clean_url not in self.discovered_urls:
                        self.discovered_urls.add(clean_url)
                        if self._is_same_domain(clean_url):
                            self.internal_links.add(clean_url)
                            self.urls_to_visit.append(clean_url)
                        else:
                            self.external_links.add(clean_url)

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request error for {current_url}: {e}")
            except Exception as e:
                self.logger.error(f"Error during crawl of {current_url}: {e}")

            # This is a very simplistic way to handle depth. For more complex depth,
            # you might need to store (URL, depth) tuples in urls_to_visit.
            # For now, assuming new links from a popped URL are one level deeper.
            # A more robust depth tracking would involve queueing tuples of (url, depth).
            # For simplicity, we'll increment depth after processing a batch/level.
            if len(self.urls_to_visit) == 0: # If all URLs at current depth processed
                current_depth += 1


        self.logger.info(f"Crawl finished. Visited {len(self.visited_urls)} URLs.")
        self.logger.debug(f"Discovered: {len(self.discovered_urls)} unique URLs.")
        self.logger.debug(f"Internal links: {len(self.internal_links)}")
        self.logger.debug(f"External links: {len(self.external_links)}")
        return list(self.internal_links), list(self.external_links)