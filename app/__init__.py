"""
Plex Online Media Sources Manager - Main Application Package

A privacy-first web application for managing Plex Online Media Sources
with OAuth authentication and GDPR compliance.
"""

__version__ = "0.1.0"
__author__ = "CCCP-PS"
__email__ = "213192498+cccp-ps@users.noreply.github.com"

# Re-export commonly used modules for convenience
from . import api, core, middleware, models, schemas, services, utils

__all__ = [
    "api",
    "core",
    "middleware",
    "models",
    "schemas",
    "services",
    "utils",
    "__version__",
]
