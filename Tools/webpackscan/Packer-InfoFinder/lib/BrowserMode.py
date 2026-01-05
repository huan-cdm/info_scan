#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
BrowserMode module for capturing dynamically loaded JS files using Playwright.

This module implements headless browser mode to discover JS files that require
JavaScript execution to load, addressing Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 5.1, 5.2, 5.3.
"""

import time
import asyncio
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse

from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource, JsDiscoveryRecord


class PlaywrightNotInstalledError(Exception):
    """Exception raised when Playwright is not installed."""
    pass


class BrowserMode:
    """
    Browser mode for capturing dynamically loaded JS files using Playwright.
    
    Uses a headless browser to load pages and intercept network requests,
    capturing all JS files that are loaded dynamically via JavaScript execution.
    
    Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 5.1, 5.2, 5.3
    
    Attributes:
        options: Command line options containing proxy, cookie, headers, etc.
        timeout: Browser wait timeout in milliseconds (default 10000)
        intercepted_js: List of discovered JS file records
        intercepted_urls: Set of intercepted JS URLs for deduplication
    """
    
    def __init__(self, options):
        """
        Initialize the BrowserMode.
        
        Checks if Playwright is installed and initializes configuration.
        
        Args:
            options: Command line options object
        
        Raises:
            PlaywrightNotInstalledError: If Playwright is not installed
        
        Requirements: 2.1
        """
        self.log = creatLog().get_logger()
        self.options = options
        self.timeout = getattr(options, 'browser_timeout', 10000)
        self.intercepted_js: List[JsDiscoveryRecord] = []
        self.intercepted_urls: Set[str] = set()
        self._playwright = None
        self._browser = None
        
        # Check Playwright installation
        self._check_playwright_installation()
    
    def _check_playwright_installation(self) -> None:
        """
        Check if Playwright is installed and available.
        
        Raises:
            PlaywrightNotInstalledError: If Playwright is not installed
        
        Requirements: 2.1
        """
        try:
            import playwright
            from playwright.async_api import async_playwright
            self.log.debug("[BrowserMode] Playwright is installed")
        except ImportError:
            raise PlaywrightNotInstalledError("Playwright is not installed")


    def _is_js_request(self, url: str, resource_type: str = None) -> bool:
        """
        Check if a request is for a JavaScript file.
        
        Filters requests by URL extension (.js, .mjs) or resource type.
        
        Args:
            url: The request URL
            resource_type: The resource type from Playwright (optional)
        
        Returns:
            True if the request is for a JS file, False otherwise
        
        Requirements: 2.2, 2.3
        """
        # Check resource type if available
        if resource_type and resource_type == 'script':
            return True
        
        # Parse URL and check extension
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Remove query string from path for extension check
        if '?' in path:
            path = path.split('?')[0]
        
        # Check for JS file extensions
        if path.endswith('.js') or path.endswith('.mjs'):
            return True
        
        return False

    def _setup_request_interception(self, page) -> None:
        """
        Set up network request interception on a Playwright page.
        
        Listens to 'request' events and filters for JavaScript files,
        storing intercepted JS URLs.
        
        Args:
            page: Playwright page object
        
        Requirements: 2.2, 2.3
        """
        def handle_request(request):
            url = request.url
            resource_type = request.resource_type
            
            if self._is_js_request(url, resource_type):
                # Avoid duplicates
                if url not in self.intercepted_urls:
                    self.intercepted_urls.add(url)
                    record = JsDiscoveryRecord(
                        url=url,
                        source=DiscoverySource.BROWSER_INTERCEPT,
                        parent_url=page.url,
                        depth=0,
                        timestamp=time.time()
                    )
                    self.intercepted_js.append(record)
                    self.log.debug(f"[BrowserMode] Intercepted JS: {url}")
        
        page.on("request", handle_request)

    def _apply_proxy_settings(self, browser_options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply proxy settings to browser launch options.
        
        Reads proxy configuration from options and configures browser
        launch options accordingly.
        
        Args:
            browser_options: Dictionary of browser launch options
        
        Returns:
            Updated browser options with proxy configuration
        
        Requirements: 5.1
        """
        proxy = getattr(self.options, 'proxy', None)
        
        if proxy:
            # Parse proxy string (format: http://host:port or host:port)
            if not proxy.startswith(('http://', 'https://', 'socks5://')):
                proxy = f"http://{proxy}"
            
            browser_options['proxy'] = {
                'server': proxy
            }
            self.log.debug(f"[BROWSER] 使用代理: {proxy}")
        
        return browser_options

    async def _inject_cookies(self, context, url: str) -> None:
        """
        Inject cookies into the browser context.
        
        Parses cookie string from options and adds cookies to the
        browser context before navigation.
        
        Args:
            context: Playwright browser context
            url: Target URL for determining cookie domain
        
        Requirements: 5.2
        """
        cookie_str = getattr(self.options, 'cookie', None)
        
        if not cookie_str:
            return
        
        # Parse the target URL to get domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port from domain if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        cookies = []
        
        # Parse cookie string (format: "name1=value1; name2=value2")
        for cookie_part in cookie_str.split(';'):
            cookie_part = cookie_part.strip()
            if '=' in cookie_part:
                name, value = cookie_part.split('=', 1)
                cookies.append({
                    'name': name.strip(),
                    'value': value.strip(),
                    'domain': domain,
                    'path': '/'
                })
        
        if cookies:
            await context.add_cookies(cookies)
            self.log.debug(f"[BROWSER] 注入 {len(cookies)} 个cookies")

    def _set_custom_headers(self, context_options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set custom HTTP headers for the browser context.
        
        Reads custom headers from options and configures them for
        all browser requests.
        
        Args:
            context_options: Dictionary of context options
        
        Returns:
            Updated context options with custom headers
        
        Requirements: 5.3
        """
        extra_headers = {}
        
        # Add custom header from options
        head = getattr(self.options, 'head', None)
        if head and ':' in head:
            key, value = head.split(':', 1)
            extra_headers[key.strip()] = value.strip()
        
        if extra_headers:
            context_options['extra_http_headers'] = extra_headers
            self.log.debug(f"[BROWSER] 设置自定义头: {list(extra_headers.keys())}")
        
        return context_options


    async def scan_with_browser(self, url: str) -> List[str]:
        """
        Scan a URL using a headless browser and capture all JS requests.
        
        Launches a browser with configured options, creates a context with
        cookies and headers, sets up request interception, navigates to the
        URL, waits for the configured timeout, and returns collected JS URLs.
        
        Args:
            url: The target URL to scan
        
        Returns:
            List of discovered JS file URLs
        
        Requirements: 2.1, 2.4, 2.5
        """
        from playwright.async_api import async_playwright
        
        self.log.info(f"[BROWSER] 正在扫描: {url}")
        
        # Reset state for new scan
        self.intercepted_js.clear()
        self.intercepted_urls.clear()
        
        browser = None
        playwright = None
        
        try:
            playwright = await async_playwright().start()
            
            # Prepare browser launch options
            browser_options = {
                'headless': True
            }
            
            # Apply proxy settings
            browser_options = self._apply_proxy_settings(browser_options)
            
            # Launch browser
            browser = await playwright.chromium.launch(**browser_options)
            
            # Prepare context options
            context_options = {}
            
            # Set custom headers
            context_options = self._set_custom_headers(context_options)
            
            # Handle SSL verification in context
            ssl_flag = int(getattr(self.options, 'ssl_flag', 0))
            if ssl_flag:
                context_options['ignore_https_errors'] = True
            
            # Create browser context
            context = await browser.new_context(**context_options)
            
            # Inject cookies
            await self._inject_cookies(context, url)
            
            # Create page
            page = await context.new_page()
            
            # Setup request interception
            self._setup_request_interception(page)
            
            # Handle popup events gracefully
            async def handle_popup(popup):
                self.log.debug(f"[BrowserMode] Popup detected: {popup.url}")
                # Setup interception on popup too
                self._setup_request_interception(popup)
            
            context.on("page", handle_popup)
            
            # Navigate to URL with timeout handling
            try:
                await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout)
                self.log.debug(f"[BROWSER] 页面加载完成")
            except Exception as nav_error:
                self.log.debug(f"[BROWSER] 导航问题(继续): {str(nav_error)}")
            
            # Wait for additional dynamic content to load
            wait_time = min(self.timeout / 1000, 10)  # Convert to seconds, max 10s
            self.log.debug(f"[BrowserMode] Waiting {wait_time}s for dynamic content...")
            await asyncio.sleep(wait_time)
            
            # Try to wait for network idle
            try:
                await page.wait_for_load_state('networkidle', timeout=5000)
            except Exception:
                # Network idle timeout is acceptable
                pass
            
        except Exception as e:
            self.log.error(f"[BrowserMode] Browser scan error: {str(e)}")
        
        finally:
            # Cleanup
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()
        
        return list(self.intercepted_urls)

    def scan(self, url: str) -> List[str]:
        """
        Synchronous wrapper for scan_with_browser.
        
        Provides a synchronous interface for the async browser scanning.
        
        Args:
            url: The target URL to scan
        
        Returns:
            List of discovered JS file URLs
        
        Requirements: 2.1
        """
        return asyncio.run(self.scan_with_browser(url))

    def get_discovered_js(self) -> List[JsDiscoveryRecord]:
        """
        Get all discovered JS file records.
        
        Returns:
            List of JsDiscoveryRecord objects for all discovered JS files
        """
        return self.intercepted_js

    def get_discovered_js_urls(self) -> List[str]:
        """
        Get all discovered JS file URLs.
        
        Returns:
            List of JS file URLs (deduplicated)
        """
        return list(self.intercepted_urls)

    def reset(self):
        """Reset the browser mode state for a new scan."""
        self.intercepted_js.clear()
        self.intercepted_urls.clear()
