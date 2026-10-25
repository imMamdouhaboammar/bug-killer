import os

BASE_STORAGE = "/var/app/data/uploads"

def load_user_document(user_filename):
    # Vulnerable Path Traversal via unconstrained os.path.join
    filepath = os.path.join(BASE_STORAGE, user_filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()
