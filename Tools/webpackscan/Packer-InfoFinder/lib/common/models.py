# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
Data models for JS discovery tracking.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class DiscoverySource(Enum):
    """Enum representing the method by which a JS file was discovered.
    
    Validates: Requirements 4.1
    """
    STATIC_HTML = "static_html"
    IFRAME = "iframe"
    INLINE_PATTERN = "inline_pattern"
    BROWSER_INTERCEPT = "browser_intercept"


@dataclass
class JsDiscoveryRecord:
    """Record containing metadata about a discovered JS file.
    
    Validates: Requirements 4.1
    
    Attributes:
        url: The URL of the discovered JS file
        source: The discovery method (DiscoverySource enum)
        parent_url: The URL of the page where this JS was discovered
        depth: The iframe recursion depth (0 for main page)
        timestamp: Unix timestamp when the JS was discovered
    """
    url: str
    source: DiscoverySource
    parent_url: str
    depth: int
    timestamp: float
