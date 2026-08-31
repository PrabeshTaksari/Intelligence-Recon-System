"""Health check endpoint."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.schemas.common import HealthResponse
from app.core.config import settings

router = APIRouter(tags=["health"])


class ConfigResponse(BaseModel):
    """Frontend configuration response."""
    api_base_url: str
    status: str = "ok"


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="ok")


@router.get("/config", response_model=ConfigResponse)
async def get_config(request: Request):
    """
    Get frontend configuration (read-only).
    Returns the API base URL using the request host so that both
    http://localhost:8080 and http://0.0.0.0:8080 work and show the same content.
    """
    # Use the host the client used (localhost or 0.0.0.0) so both URLs behave the same
    base_url = str(request.base_url).rstrip("/")
    return ConfigResponse(
        api_base_url=base_url,
        status="ok"
    )


