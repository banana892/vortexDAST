"""
VortexDAST – adapters/
────────────────────────────────────────────────────────────────────────────
External-tool integrations for the orchestration layer.

Each module here defines a :class:`~core.orchestrator.ToolAdapter` subclass
that wraps one best-of-breed specialist (nuclei, nmap, httpx, sqlmap, …),
runs it as a subprocess, and maps its structured output into VortexDAST
:class:`~modules.base.Finding` objects.

Adapters are auto-discovered: drop a file here, subclass ``ToolAdapter``, set
``name`` + ``binary``, and it is registered on the next run — no wiring needed
(see :func:`core.orchestrator.discover_adapters`).
"""
