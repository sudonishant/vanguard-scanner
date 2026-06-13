import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url, max_pages=15):
        self.base_url = base_url
        self.target_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited_urls = set()
        self.forms_found = []
        self.links_found = set()

    def is_same_domain(self, url):
        """Check if the URL belongs to the target domain."""
        return urlparse(url).netloc == self.target_domain

    def get_links_and_forms(self, url):
        """Fetch a page, extract links and forms."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vanguard/1.0"
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code != 200:
                return set(), []
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract Links
            links = set()
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                # Resolve relative URLs
                full_url = urljoin(url, href)
                # Clean URL (remove fragments like #section)
                clean_url = full_url.split("#")[0]
                if self.is_same_domain(clean_url):
                    links.add(clean_url)
            
            # Extract Forms
            forms = []
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action", "")
                method = form_tag.get("method", "get").lower()
                inputs = []
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name")
                    input_type = input_tag.get("type", "text")
                    if input_name:
                        inputs.append({
                            "name": input_name,
                            "type": input_type,
                            "value": input_tag.get("value", "")
                        })
                
                forms.append({
                    "url": url,
                    "action": urljoin(url, action),
                    "method": method,
                    "inputs": inputs
                })

            return links, forms

        except Exception as e:
            # Silently handle connection timeouts or certificate errors
            return set(), []

    def crawl(self):
        """Crawl the website up to max_pages."""
        to_visit = [self.base_url]
        
        while to_visit and len(self.visited_urls) < self.max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in self.visited_urls:
                continue
                
            self.visited_urls.add(current_url)
            
            links, forms = self.get_links_and_forms(current_url)
            self.forms_found.extend(forms)
            
            for link in links:
                if link not in self.visited_urls and link not in to_visit:
                    to_visit.append(link)
                    self.links_found.add(link)
                    
        return list(self.visited_urls), self.forms_found
