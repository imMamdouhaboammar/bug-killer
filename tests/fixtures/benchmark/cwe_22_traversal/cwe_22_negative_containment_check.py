import os

BASE_STORAGE = os.path.abspath("/var/app/data/uploads")

def load_user_document_safe(user_filename):
    # Safe path traversal defense: canonical path resolution and strict prefix containment check
    resolved_path = os.path.abspath(os.path.join(BASE_STORAGE, user_filename))
    if not (resolved_path == BASE_STORAGE or resolved_path.startswith(BASE_STORAGE + os.sep)):
        raise PermissionError("Attempted path traversal outside designated root directory")
    with open(resolved_path, "r", encoding="utf-8") as f:
        return f.read()
