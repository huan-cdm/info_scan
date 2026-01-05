#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
IframeParser module for detecting and recursively parsing iframe/frame tags.

This module implements iframe recursive parsing to discover JS files loaded
within iframes, addressing Requirements 1.1, 1.2, 1.3, 1.4, 1.5.
"""

import requests
import warnings
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource, JsDiscoveryRecord
from lib.common.utils import Utils


class IframeParser:
    """
    Parser for detecting and recursively processing iframe/frame tags.
    
    Validates: Requirements 1.1, 1.5
    
    Attributes:
        base_url: The base URL for resolving relative paths
        options: Command line options containing proxy, cookie, headers, etc.
        max_depth: Maximum recursion depth for iframe parsing (default 3)
        visited_urls: Set of already visited URLs for deduplication
        discovered_js: List of discovered JS file records
    """
    
    def __init__(self, base_url: str, options, max_depth: int = 3):
        """
        Initialize the IframeParser.
        
        Args:
            base_url: The base URL for resolving relative paths
            options: Command line options object
            max_depth: Maximum recursion depth (default 3)
        
        Requirements: 1.1, 1.5
        """
        warnings.filterwarnings('ignore')
        self.base_url = base_url
        self.options = options
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.discovered_js: List[JsDiscoveryRecord] = []
        self.log = creatLog().get_logger()
        self.proxy_data = Utils().build_proxies(getattr(options, 'proxy', None))
        self._init_headers()

    def _init_headers(self):
        """Initialize HTTP headers for requests."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
        }
        
        # Add custom header if provided
        if hasattr(self.options, 'head') and self.options.head and ':' in self.options.head:
            key, value = self.options.head.split(':', 1)
            headers[key.strip()] = value.strip()
        
        # Add cookie if provided
        if hasattr(self.options, 'cookie') and self.options.cookie:
            headers["Cookie"] = self.options.cookie
        
        self.headers = headers

    def extract_iframe_urls(self, html_content: str) -> List[str]:
        """
        Extract all iframe and frame src URLs from HTML content.
        
        Parses HTML with BeautifulSoup and extracts src attributes from
        both iframe and frame tags. Handles both quoted and unquoted attributes.
        
        Args:
            html_content: The HTML content to parse (can be string or BeautifulSoup)
        
        Returns:
            List of iframe/frame src URLs (may be relative or absolute)
        
        Requirements: 1.1
        """
        # Handle both string and BeautifulSoup input
        if isinstance(html_content, BeautifulSoup):
            soup = html_content
        else:
            soup = BeautifulSoup(html_content, "html.parser")
        
        iframe_urls = []
        
        # Find all iframe and frame tags
        for tag in soup.find_all(['iframe', 'frame']):
            src = tag.get('src')
            if src:
                # Strip whitespace and skip empty/javascript/data URLs
                src = src.strip()
                if src and not src.startswith(('javascript:', 'data:', 'about:')):
                    iframe_urls.append(src)
        
        return iframe_urls

    def resolve_url(self, relative_url: str, base_url: Optional[str] = None) -> str:
        """
        Resolve a relative URL to an absolute URL.
        
        Uses urllib.parse.urljoin for URL resolution, handling edge cases
        including absolute URLs, protocol-relative URLs, and fragment-only URLs.
        
        Args:
            relative_url: The URL to resolve (may be relative or absolute)
            base_url: The base URL for resolution (defaults to self.base_url)
        
        Returns:
            The resolved absolute URL
        
        Requirements: 1.4
        """
        if base_url is None:
            base_url = self.base_url
        
        # Handle empty or None URLs
        if not relative_url:
            return base_url
        
        relative_url = relative_url.strip()
        
        # Skip fragment-only URLs (they refer to the same page)
        if relative_url.startswith('#'):
            return base_url
        
        # Handle protocol-relative URLs (//example.com/path)
        if relative_url.startswith('//'):
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme}:{relative_url}"
        
        # Handle absolute URLs (already complete)
        if relative_url.startswith(('http://', 'https://')):
            return relative_url
        
        # Use urljoin for relative URL resolution
        return urljoin(base_url, relative_url)

    def _fetch_url(self, url: str) -> Optional[str]:
        """
        Fetch content from a URL with error handling.
        
        Args:
            url: The URL to fetch
        
        Returns:
            The response text content, or None if request failed
        """
        try:
            ssl_flag = int(getattr(self.options, 'ssl_flag', 0))
            kwargs = {
                "url": url,
                "headers": self.headers,
                "allow_redirects": True,
                "timeout": (10, 30)
            }
            
            if self.proxy_data:
                kwargs["proxies"] = self.proxy_data
            if ssl_flag:
                kwargs["verify"] = False
            
            response = requests.get(**kwargs)
            
            # Check if response is HTML
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type or 'application/xhtml' in content_type:
                return response.text
            
            # Also accept responses without explicit content-type if they look like HTML
            if response.text.strip().startswith(('<!DOCTYPE', '<html', '<HTML')):
                return response.text
            
            self.log.debug(f"[IframeParser] Skipping non-HTML content: {url}")
            return None
            
        except requests.exceptions.Timeout:
            self.log.warning(f"[IframeParser] Timeout fetching iframe: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            self.log.warning(f"[IframeParser] Connection error for iframe: {url} - {str(e)}")
            return None
        except Exception as e:
            self.log.warning(f"[IframeParser] Error fetching iframe: {url} - {str(e)}")
            return None


    def _extract_js_from_html(self, soup: BeautifulSoup, parent_url: str, depth: int) -> List[str]:
        """
        Extract JS file URLs from parsed HTML.
        
        Args:
            soup: BeautifulSoup parsed HTML
            parent_url: The URL of the page containing the JS references
            depth: Current iframe recursion depth
        
        Returns:
            List of JS file URLs found in the HTML
        """
        js_urls = []
        
        # Extract from script tags with src attribute
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                src = src.strip()
                if src and not src.startswith(('javascript:', 'data:')):
                    resolved_url = self.resolve_url(src, parent_url)
                    js_urls.append(resolved_url)
        
        # Extract from link tags that reference JS files
        for link in soup.find_all('link'):
            href = link.get('href')
            if href and href.endswith('.js'):
                resolved_url = self.resolve_url(href.strip(), parent_url)
                js_urls.append(resolved_url)
        
        return js_urls

    def parse_iframe_recursive(self, url: str, depth: int = 0, parent_url: Optional[str] = None) -> List[str]:
        """
        Recursively parse iframe content and discover JS files.
        
        Checks depth against max_depth, checks URL against visited_urls set,
        requests iframe URL and parses response, then recursively processes
        nested iframes.
        
        Args:
            url: The iframe URL to parse
            depth: Current recursion depth (default 0)
            parent_url: The URL of the parent page (for tracking)
        
        Returns:
            List of discovered JS file URLs
        
        Requirements: 1.2, 1.3, 1.5
        """
        # Check recursion depth limit
        if depth > self.max_depth:
            self.log.debug(f"[IFRAME] 达到最大深度 ({self.max_depth})，停止递归")
            return []
        
        # Resolve URL to absolute
        resolved_url = self.resolve_url(url, parent_url or self.base_url)
        
        # Check for duplicate URLs (deduplication)
        if resolved_url in self.visited_urls:
            self.log.debug(f"[IFRAME] 跳过已访问: {resolved_url}")
            return []
        
        # Mark URL as visited
        self.visited_urls.add(resolved_url)
        
        self.log.debug(f"[IFRAME] 解析 (深度{depth}): {resolved_url}")
        
        # Fetch iframe content
        html_content = self._fetch_url(resolved_url)
        if html_content is None:
            return []
        
        # Parse HTML
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract JS files from this iframe
        js_urls = self._extract_js_from_html(soup, resolved_url, depth)
        
        # Create discovery records for found JS files
        import time
        for js_url in js_urls:
            record = JsDiscoveryRecord(
                url=js_url,
                source=DiscoverySource.IFRAME,
                parent_url=resolved_url,
                depth=depth,
                timestamp=time.time()
            )
            self.discovered_js.append(record)
        
        # Find nested iframes and process recursively
        nested_iframe_urls = self.extract_iframe_urls(soup)
        for nested_url in nested_iframe_urls:
            nested_js = self.parse_iframe_recursive(
                url=nested_url,
                depth=depth + 1,
                parent_url=resolved_url
            )
            js_urls.extend(nested_js)
        
        return js_urls

    def get_discovered_js(self) -> List[JsDiscoveryRecord]:
        """
        Get all discovered JS file records.
        
        Returns:
            List of JsDiscoveryRecord objects for all discovered JS files
        """
        return self.discovered_js

    def get_discovered_js_urls(self) -> List[str]:
        """
        Get all discovered JS file URLs.
        
        Returns:
            List of JS file URLs (deduplicated)
        """
        return list(set(record.url for record in self.discovered_js))

    def reset(self):
        """Reset the parser state for a new scan."""
        self.visited_urls.clear()
        self.discovered_js.clear()
