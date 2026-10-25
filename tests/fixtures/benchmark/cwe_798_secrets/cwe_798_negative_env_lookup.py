import os

def authenticate_internal_worker_safe():
    # Safe retrieval of sensitive credentials from runtime environment
    token = os.environ.get("INTERNAL_SERVICE_TOKEN")
    if not token:
        raise RuntimeError("Missing required environment secret INTERNAL_SERVICE_TOKEN")
    return {"Authorization": f"Bearer {token}"}
