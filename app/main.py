"""
Main FastAPI application for Plex Online Media Sources Manager.

This module initializes the FastAPI application with security middleware,
CORS configuration, authentication routes, media source routes, exception handlers,
and health monitoring endpoints.

Privacy-first architecture with GDPR compliance and secure token management.
"""

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.api.routes import auth, media_sources
from app.config import Settings, get_settings
from app.middleware.security import (
    CSRFProtectionMiddleware,
    RateLimitingMiddleware, 
    SecurityHeadersMiddleware
)
from app.services.plex_service import PlexMediaSourceService
from app.utils.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConnectionException,
    PlexAPIException,
    RateLimitException,
    ValidationException,
    authentication_exception_handler,
    authorization_exception_handler,
    connection_exception_handler,
    plexapi_exception_handler,
    pydantic_validation_exception_handler,
    rate_limit_exception_handler,
    validation_exception_handler,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # pyright: ignore[reportUnusedParameter]
    """
    Application lifespan manager for startup and shutdown events.
    
    Handles application initialization and cleanup tasks.
    """
    # Startup
    logger.info("Starting Plex Online Media Sources Manager...")
    
    # Initialize services and validate configuration
    settings = get_settings()
    logger.info("Configuration loaded successfully")
    
    # Validate PlexAPI configuration
    try:
        # Test basic connectivity (without authentication)
        logger.info("Validating PlexAPI configuration...")
        # Note: We don't test connectivity here since it requires auth tokens
        logger.info("Application startup completed successfully")
    except Exception as e:
        logger.error(f"Application startup failed: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Plex Online Media Sources Manager...")
    logger.info("Application shutdown completed")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Sets up middleware, routes, exception handlers, and security features
    following privacy-first principles and security best practices.
    
    Returns:
        Configured FastAPI application instance
    """
    # Get application settings
    settings = get_settings()
    
    # Initialize FastAPI application
    app = FastAPI(
        title="Plex Online Media Sources Manager",
        description=(
            "A privacy-first web application for managing Plex Online Media Sources. "
            "Provides OAuth authentication and easy opt-out functionality while "
            "maintaining GDPR compliance and data minimization principles."
        ),
        version="0.1.0",
        docs_url="/docs" if settings.environment == "development" else None,
        redoc_url="/redoc" if settings.environment == "development" else None,
        lifespan=lifespan,
        # Security configuration
        openapi_url="/openapi.json" if settings.environment == "development" else None,
    )
    
    # Configure CORS middleware with security settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type", 
            "X-CSRF-Token",
            "X-Requested-With",
            "Accept",
            "Origin",
            "User-Agent",
            "DNT",
            "Cache-Control",
            "If-Modified-Since",
            "Keep-Alive",
            "X-Requested-With"
        ],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining", 
            "X-RateLimit-Reset"
        ],
        max_age=86400,  # 24 hours
    )
    
    # Add security headers middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        include_hsts=settings.environment == "production",
        include_csp=True,
        include_security_headers=True,
        hsts_max_age=31536000,  # 1 year
        hsts_include_subdomains=True,
        hsts_preload=True,
        csp_policy=(
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self' https://plex.tv https://*.plex.tv; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests"
        ),
        cors_allowed_origins=settings.cors_origins_list,
        cors_allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        cors_allowed_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        cors_allow_credentials=True,
        custom_server_header="Plex-OMS-Service/0.1.0",
        secure_cookies=settings.environment == "production"
    )
    
    # Add rate limiting middleware
    app.add_middleware(
        RateLimitingMiddleware,
        default_rate_limit="100/minute",
        endpoint_limits={
            "/auth/login": "10/minute",
            "/auth/callback": "10/minute", 
            "/auth/refresh": "20/minute",
            "/api/media-sources/disable-all": "5/minute",
            "/health": "60/minute"
        },
        enabled=True
    )
    
    # Add CSRF protection middleware (exclude health and docs endpoints)
    app.add_middleware(
        CSRFProtectionMiddleware,
        excluded_paths=[
            "/health",
            "/docs",
            "/redoc", 
            "/openapi.json",
            "/auth/login",  # OAuth has its own state protection
            "/auth/callback"  # OAuth callback uses state validation
        ],
        token_header="X-CSRF-Token",
        token_ttl=3600  # 1 hour
    )
    
    # Register exception handlers using proper FastAPI approach
    # Cast the handlers to the proper type to avoid type checker issues
    app.add_exception_handler(PlexAPIException, plexapi_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(AuthenticationException, authentication_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(AuthorizationException, authorization_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(ValidationException, validation_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(ConnectionException, connection_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(RateLimitException, rate_limit_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(ValidationError, pydantic_validation_exception_handler)  # pyright: ignore[reportArgumentType]
    
    # Register authentication routes
    app.include_router(auth.router)
    
    # Register media sources routes  
    app.include_router(media_sources.router)
    
    # Add health check endpoint
    @app.get(
        "/health",
        tags=["monitoring"],
        summary="Application health check",
        description="Returns application health status with PlexAPI connectivity check",
        responses={
            200: {
                "description": "Application health status",
                "content": {
                    "application/json": {
                        "example": {
                            "status": "healthy",
                            "timestamp": "2024-01-01T00:00:00Z",
                            "version": "0.1.0",
                            "plex_api": {
                                "connected": True,
                                "response_time_ms": 150
                            }
                        }
                    }
                }
            }
        }
    )
    async def health_check(request: Request) -> JSONResponse:  # pyright: ignore[reportUnusedParameter]
        """
        Get application health status.
        
        Performs health checks including PlexAPI connectivity
        and returns overall application status.
        
        Returns:
            JSON response with health status, timestamp, and service checks
        """
        start_time = time.time()
        health_data: dict[str, str | dict[str, bool | int | str]] = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "0.1.0"
        }
        
        # Check PlexAPI connectivity
        plex_service = PlexMediaSourceService()
        try:
            # Attempt connectivity check (this doesn't require authentication)
            connectivity_start = time.time()
            is_connected = await plex_service.check_connectivity()
            connectivity_time = int((time.time() - connectivity_start) * 1000)
            
            health_data["plex_api"] = {
                "connected": is_connected,
                "response_time_ms": connectivity_time
            }
            
            if not is_connected:
                health_data["status"] = "degraded"
                
        except Exception as e:
            health_data["status"] = "degraded"
            health_data["plex_api"] = {
                "connected": False,
                "error": "PlexAPI connectivity check failed",
                "response_time_ms": int((time.time() - start_time) * 1000)
            }
            logger.warning(f"Health check PlexAPI connectivity failed: {str(e)}")
        
        # Determine overall status code
        status_code = status.HTTP_200_OK
        
        return JSONResponse(
            content=health_data,
            status_code=status_code,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
    
    # Add root endpoint redirect
    @app.get(
        "/",
        include_in_schema=False,
        summary="Root endpoint",
        description="Redirects to documentation or health check"
    )
    async def root() -> JSONResponse:
        """Root endpoint providing basic application information."""
        return JSONResponse(
            content={
                "message": "Plex Online Media Sources Manager API",
                "version": "0.1.0",
                "docs": "/docs" if settings.environment == "development" else None,
                "health": "/health"
            },
            status_code=status.HTTP_200_OK
        )
    
    logger.info("FastAPI application created and configured successfully")
    return app


# Create the application instance
app = create_app() 