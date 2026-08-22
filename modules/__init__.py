"""
VortexDAST – modules/__init__.py
Exposes all implemented scanner modules for orchestrator discovery.
"""

from .base import BaseScannerModule, Finding, Severity
from .headers_audit import HeadersAuditModule
from .xss_check import XSSCheckModule
from .sqli_check import SQLiCheckModule
from .ssrf_check import SSRFCheckModule

__all__ = [
    "BaseScannerModule",
    "Finding",
    "Severity",
    "HeadersAuditModule",
    "XSSCheckModule",
    "SQLiCheckModule",
    "SSRFCheckModule",
]
