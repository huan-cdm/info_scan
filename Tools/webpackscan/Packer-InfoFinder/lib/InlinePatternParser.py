#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
InlinePatternParser module for detecting dynamic script loading patterns in inline JavaScript.

This module implements pattern-based detection of dynamically loaded scripts,
addressing Requirements 3.1, 3.2, 3.3, 3.4.
"""

import re
import time
from typing import List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin

from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource, JsDiscoveryRecord


@dataclass
class DynamicUrlMatch:
    """
    Represents a URL match found in inline JavaScript.
    
    Attributes:
        url: The extracted URL (may be partial if concatenated)
        pattern_type: The type of pattern that matched (e.g., 'createElement_script')
        is_complete: Whether the URL is complete or partial
        context: The surrounding code context for debugging
    """
    url: str
    pattern_type: str
    is_complete: bool
    context: str = ""


class InlinePatternParser:
    """
    Parser for detecting dynamic script loading patterns in inline JavaScript.
    
    Detects common patterns like:
    - document.createElement('script') with src assignment
    - script.src = '...' assignments
    - setAttribute('src', '...') calls
    - iframe.src = '...' assignments
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.4
    """
    
    # Regex patterns for dynamic script loading detection
    PATTERNS = {
        # Matches: document.createElement('script') or document.createElement("script")
        'createElement_script': re.compile(
            r"document\.createElement\s*\(\s*['\"]script['\"]\s*\)",
            re.IGNORECASE
        ),
        # Matches: .src = 'url' or .src = "url" or .src='url'
        'src_assign': re.compile(
            r"\.src\s*=\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        # Matches: setAttribute('src', 'url') or setAttribute("src", "url")
        'setAttribute_src': re.compile(
            r"\.setAttribute\s*\(\s*['\"]src['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        # Matches: iframe.src = 'url' or variations like el.src where el is iframe
        'iframe_src_assign': re.compile(
            r"(?:iframe|frame)(?:\w*)\.src\s*=\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        # Matches: .src = variable + 'string' or 'string' + variable (concatenation)
        'src_concat': re.compile(
            r"\.src\s*=\s*([^;]+);",
            re.IGNORECASE
        ),
    }
    
    # Pattern to extract string literals from concatenation
    STRING_LITERAL_PATTERN = re.compile(r"['\"]([^'\"]+)['\"]")
    
    def __init__(self, base_url: str = ""):
        """
        Initialize the InlinePatternParser.
        
        Args:
            base_url: The base URL for resolving relative paths
        """
        self.base_url = base_url
        self.log = creatLog().get_logger()
        self.discovered_js: List[JsDiscoveryRecord] = []
        self.discovered_iframes: List[str] = []


    def extract_dynamic_urls(self, js_content: str, parent_url: Optional[str] = None) -> List[DynamicUrlMatch]:
        """
        Extract dynamically loaded URLs from JavaScript code.
        
        Detects patterns like:
        - document.createElement('script') followed by src assignment
        - .src = '...' assignments
        - setAttribute('src', '...') calls
        - iframe.src = '...' assignments
        
        Args:
            js_content: The JavaScript code to analyze
            parent_url: The URL of the page containing this JS (for context)
        
        Returns:
            List of DynamicUrlMatch objects containing extracted URLs
        
        Requirements: 3.1, 3.2, 3.4
        """
        matches: List[DynamicUrlMatch] = []
        
        if not js_content:
            return matches
        
        # Track if we've seen createElement('script') to associate with src assignments
        has_create_script = bool(self.PATTERNS['createElement_script'].search(js_content))
        
        # Extract direct .src = 'url' assignments
        for match in self.PATTERNS['src_assign'].finditer(js_content):
            url = match.group(1).strip()
            if self._is_valid_url(url):
                # Get context (surrounding code)
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                matches.append(DynamicUrlMatch(
                    url=url,
                    pattern_type='src_assign',
                    is_complete=True,
                    context=context
                ))
        
        # Extract setAttribute('src', 'url') patterns
        for match in self.PATTERNS['setAttribute_src'].finditer(js_content):
            url = match.group(1).strip()
            if self._is_valid_url(url):
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                matches.append(DynamicUrlMatch(
                    url=url,
                    pattern_type='setAttribute_src',
                    is_complete=True,
                    context=context
                ))
        
        # Extract iframe.src = 'url' patterns
        for match in self.PATTERNS['iframe_src_assign'].finditer(js_content):
            url = match.group(1).strip()
            if self._is_valid_url(url):
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                matches.append(DynamicUrlMatch(
                    url=url,
                    pattern_type='iframe_src_assign',
                    is_complete=True,
                    context=context
                ))
                # Also track iframe URLs separately
                self.discovered_iframes.append(url)
        
        # Handle concatenation patterns (partial URLs)
        for match in self.PATTERNS['src_concat'].finditer(js_content):
            assignment = match.group(1).strip()
            # Skip if it's a simple string assignment (already handled above)
            if assignment.startswith(("'", '"')) and assignment.endswith(("'", '"')):
                continue
            
            # Check if it contains concatenation (+)
            if '+' in assignment:
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                matches.append(DynamicUrlMatch(
                    url=assignment,
                    pattern_type='src_concat',
                    is_complete=False,
                    context=context
                ))
        
        return matches

    def _is_valid_url(self, url: str) -> bool:
        """
        Check if a URL is valid for processing.
        
        Args:
            url: The URL to validate
        
        Returns:
            True if the URL is valid, False otherwise
        """
        if not url:
            return False
        
        # Skip javascript:, data:, about: URLs
        if url.startswith(('javascript:', 'data:', 'about:', '#')):
            return False
        
        # Skip template literals or variable references
        if '${' in url or '{{' in url:
            return False
        
        return True


    def resolve_partial_urls(self, matches: List[DynamicUrlMatch], base_url: Optional[str] = None) -> List[str]:
        """
        Attempt to resolve partial URLs from concatenation patterns.
        
        Extracts static string portions from concatenations and logs
        unresolvable patterns for debugging.
        
        Args:
            matches: List of DynamicUrlMatch objects to process
            base_url: Base URL for resolving relative paths
        
        Returns:
            List of resolved URLs (only complete/resolvable ones)
        
        Requirements: 3.3
        """
        resolved_urls: List[str] = []
        base = base_url or self.base_url
        
        for match in matches:
            if match.is_complete:
                # Resolve complete URLs
                resolved = self._resolve_url(match.url, base)
                if resolved:
                    resolved_urls.append(resolved)
            else:
                # Try to extract static portions from concatenation
                static_parts = self._extract_static_parts(match.url)
                
                if static_parts:
                    # Try to reconstruct a usable URL from static parts
                    reconstructed = self._reconstruct_url(static_parts)
                    if reconstructed:
                        resolved = self._resolve_url(reconstructed, base)
                        if resolved:
                            resolved_urls.append(resolved)
                            self.log.debug(f"[InlinePatternParser] Resolved partial URL: {reconstructed}")
                    else:
                        self.log.debug(
                            f"[InlinePatternParser] Unresolvable pattern (partial): {match.url[:100]}..."
                            if len(match.url) > 100 else
                            f"[InlinePatternParser] Unresolvable pattern (partial): {match.url}"
                        )
                else:
                    self.log.debug(
                        f"[InlinePatternParser] Unresolvable pattern (no static parts): {match.url[:100]}..."
                        if len(match.url) > 100 else
                        f"[InlinePatternParser] Unresolvable pattern (no static parts): {match.url}"
                    )
        
        return resolved_urls

    def _extract_static_parts(self, concatenation: str) -> List[str]:
        """
        Extract string literals from a concatenation expression.
        
        Args:
            concatenation: The concatenation expression (e.g., "'/js/' + name + '.js'")
        
        Returns:
            List of extracted string literals
        """
        return self.STRING_LITERAL_PATTERN.findall(concatenation)

    def _reconstruct_url(self, static_parts: List[str]) -> Optional[str]:
        """
        Attempt to reconstruct a URL from static parts.
        
        Heuristics:
        - If parts form a path-like structure, join them
        - If a part ends with .js, it's likely the end of the URL
        - If a part starts with /, it's likely a path
        
        Args:
            static_parts: List of static string parts
        
        Returns:
            Reconstructed URL if possible, None otherwise
        """
        if not static_parts:
            return None
        
        # If there's only one part and it looks like a URL, use it
        if len(static_parts) == 1:
            part = static_parts[0]
            if part.endswith('.js') or part.startswith(('http://', 'https://', '/')):
                return part
            return None
        
        # Try to join parts that look like path segments
        result_parts = []
        for part in static_parts:
            # Skip empty parts
            if not part:
                continue
            # Skip parts that look like variable placeholders
            if part in ('/', '.js', '.mjs'):
                result_parts.append(part)
            elif part.startswith(('http://', 'https://', '/')) or part.endswith(('.js', '.mjs', '/')):
                result_parts.append(part)
        
        if result_parts:
            # Join parts, being careful about slashes
            result = ''
            for part in result_parts:
                if result.endswith('/') and part.startswith('/'):
                    result += part[1:]
                elif result and not result.endswith('/') and not part.startswith('/'):
                    result += '/' + part
                else:
                    result += part
            
            # Only return if it looks like a valid URL pattern
            if result.endswith(('.js', '.mjs')) or '/' in result:
                return result
        
        return None

    def _resolve_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Resolve a URL to an absolute URL.
        
        Args:
            url: The URL to resolve
            base_url: The base URL for resolution
        
        Returns:
            Resolved absolute URL, or None if invalid
        """
        if not url or not self._is_valid_url(url):
            return None
        
        url = url.strip()
        
        # Already absolute
        if url.startswith(('http://', 'https://')):
            return url
        
        # Protocol-relative
        if url.startswith('//'):
            return 'https:' + url
        
        # Relative URL - resolve against base
        if base_url:
            return urljoin(base_url, url)
        
        return url

    def process_inline_js(self, js_content: str, parent_url: str) -> Tuple[List[str], List[str]]:
        """
        Process inline JavaScript and return discovered URLs.
        
        This is a convenience method that combines extraction and resolution.
        
        Args:
            js_content: The JavaScript code to analyze
            parent_url: The URL of the page containing this JS
        
        Returns:
            Tuple of (js_urls, iframe_urls) - lists of discovered URLs
        
        Requirements: 3.1, 3.2, 3.3, 3.4
        """
        # Reset iframe tracking for this call
        self.discovered_iframes = []
        
        # Extract matches
        matches = self.extract_dynamic_urls(js_content, parent_url)
        
        # Resolve URLs
        js_urls = self.resolve_partial_urls(matches, parent_url)
        
        # Filter JS URLs (those ending in .js or .mjs)
        js_urls = [url for url in js_urls if url.endswith(('.js', '.mjs')) or '/js/' in url]
        
        # Create discovery records
        for url in js_urls:
            record = JsDiscoveryRecord(
                url=url,
                source=DiscoverySource.INLINE_PATTERN,
                parent_url=parent_url,
                depth=0,
                timestamp=time.time()
            )
            self.discovered_js.append(record)
        
        # Resolve iframe URLs
        iframe_urls = []
        for iframe_url in self.discovered_iframes:
            resolved = self._resolve_url(iframe_url, parent_url)
            if resolved:
                iframe_urls.append(resolved)
        
        return js_urls, iframe_urls

    def get_discovered_js(self) -> List[JsDiscoveryRecord]:
        """
        Get all discovered JS file records.
        
        Returns:
            List of JsDiscoveryRecord objects
        """
        return self.discovered_js

    def reset(self):
        """Reset the parser state for a new scan."""
        self.discovered_js.clear()
        self.discovered_iframes.clear()
