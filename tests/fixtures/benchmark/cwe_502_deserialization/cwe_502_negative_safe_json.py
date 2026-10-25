import json

def restore_session_state_safe(raw_serialized_bytes):
    # Safe structured serialization parser rejecting executable objects
    text_content = raw_serialized_bytes.decode("utf-8")
    return json.loads(text_content)
