# Plex Online Media Sources Manager

A privacy-first web application for managing Plex Online Media Sources with OAuth authentication and GDPR compliance.

## Overview

This application allows Plex users to authenticate via OAuth and manage their Online Media Sources settings, with a focus on providing an easy "opt-out all" functionality while maintaining GDPR compliance.

## Technology Stack

- **Backend**: Python 3.13+ with FastAPI 0.104+
- **Plex Integration**: PlexAPI 4.15+ for OAuth and MyPlex API
- **Frontend**: TypeScript 5.3+ with React 18.2+ and TailwindCSS v4.0+
- **Authentication**: Plex OAuth 2.0 via MyPlexPinLogin
- **Testing**: pytest 7.4+ with pytest-asyncio
- **Type Checking**: basedpyright for Python, strict TypeScript config

## Development Setup

1. Ensure Python 3.13+ is installed
2. Create and activate virtual environment: `uv venv && source .venv/bin/activate`
3. Install development dependencies: `uv pip install -e ".[dev]"`
4. Run tests: `uv run pytest`
5. Check types: `uvx basedpyright`

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). 