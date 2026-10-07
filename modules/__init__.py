"""
VortexDAST – modules/__init__.py
Exposes all implemented scanner modules for orchestrator discovery.
"""

from .base import BaseScannerModule, Confidence, Finding, Severity
from .headers_audit import HeadersAuditModule
from .xss_check import XSSCheckModule
from .sqli_check import SQLiCheckModule
from .ssrf_check import SSRFCheckModule
from .traversal_check import TraversalCheckModule
from .csrf_check import CSRFCheckModule
from .dir_fuzzer import DirFuzzerModule
from .param_fuzzer import ParamFuzzerModule
from .tech_detect import TechDetectModule

__all__ = [
    "BaseScannerModule",
    "Confidence",
    "Finding",
    "Severity",
    "HeadersAuditModule",
    "XSSCheckModule",
    "SQLiCheckModule",
    "SSRFCheckModule",
    "TraversalCheckModule",
    "CSRFCheckModule",
    "DirFuzzerModule",
    "ParamFuzzerModule",
    "TechDetectModule",
]
