from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

VALID_API_KEYS = {
    "admin-dashboard-key-001": "admin_dashboard",
    "banking-site-key-002":    "banking_site",
}

def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    if not api_key or api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key"
        )
    return VALID_API_KEYS[api_key]