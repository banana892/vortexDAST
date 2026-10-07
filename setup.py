"""
VortexDAST – setup.py
─────────────────────────────────────────────────────────────────────────────
Fallback setuptools configuration for environments that do not yet support
PEP 517/518 build frontends or where legacy `python setup.py install` is
required (e.g., older CI runners, embedded build systems).

For modern installs, prefer:
    pip install -e .          # editable / development install
    pip install .             # standard install

Both commands read pyproject.toml first and fall back to this file.

console_scripts defined here
─────────────────────────────
After installation the following native terminal commands become available:

    vortex     -u https://target.example.com [options]
    vortexdast -u https://target.example.com [options]

Both resolve to `scanner.main()`.
"""

from setuptools import setup, find_packages

# Runtime dependencies kept in sync with pyproject.toml [project.dependencies]
# and requirements.txt (dev tools excluded).
INSTALL_REQUIRES = [
    "requests>=2.31.0",
    "urllib3>=2.0.0",
    "beautifulsoup4>=4.12.0",
    "lxml>=4.9.0",
    "playwright>=1.44.0",
    "pyyaml>=6.0.1",
    "rich>=13.7.0",
]

EXTRAS_REQUIRE = {
    "dev": [
        "pytest>=8.2.0",
        "pytest-cov>=5.0.0",
        "jsonschema>=4.0.0",
        "types-requests>=2.31.0",
        "types-PyYAML>=6.0.12",
        "mypy>=1.0.0",
    ],
}

setup(
    # ── Identity ──────────────────────────────────────────────────────────────
    name="vortexdast",
    version="1.0.0",
    description="Lightweight, modular Dynamic Application Security Testing (DAST) framework",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    author="VortexDAST Contributors",
    url="https://github.com/vortexdast/vortexdast",
    project_urls={
        "Bug Tracker": "https://github.com/vortexdast/vortexdast/issues",
        "Repository":  "https://github.com/vortexdast/vortexdast",
    },
    keywords=[
        "security", "dast", "pentesting", "appsec",
        "xss", "sqli", "ssrf", "vulnerability-scanner",
        "web-security", "crawler",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],

    # ── Python version gate ───────────────────────────────────────────────────
    python_requires=">=3.9",

    # ── Package discovery ─────────────────────────────────────────────────────
    # Finds core/, modules/, payloads/ sub-packages automatically.
    packages=find_packages(
        exclude=["tests", "tests.*", "*.egg-info"],
    ),
    # scanner.py lives at the project root and is not inside a package dir.
    py_modules=["scanner"],

    # ── Non-Python data files bundled into the installed package ──────────────
    include_package_data=True,
    package_data={
        "": [
            "payloads/*.json",
            "config.yaml",
        ],
    },

    # ── Dependencies ─────────────────────────────────────────────────────────
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,

    # ── CLI entrypoints ───────────────────────────────────────────────────────
    # Setuptools generates thin wrapper scripts in the environment's bin/
    # directory that call scanner.main() and propagate its integer return
    # value as the process exit code.
    entry_points={
        "console_scripts": [
            "vortex    = scanner:main",
            "vortexdast = scanner:main",
        ],
    },
)
