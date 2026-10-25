# Hardcoded sensitive production credentials in source code
INTERNAL_SERVICE_TOKEN = "sec_live_98a7fbc3410298aefb9042cda11234ef"

def authenticate_internal_worker():
    return {"Authorization": f"Bearer {INTERNAL_SERVICE_TOKEN}"}
