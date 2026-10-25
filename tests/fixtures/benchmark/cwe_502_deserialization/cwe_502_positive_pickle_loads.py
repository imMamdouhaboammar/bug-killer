import pickle

def restore_session_state(raw_serialized_bytes):
    # Vulnerable Insecure Deserialization of untrusted payload using Python pickle
    obj = pickle.loads(raw_serialized_bytes)
    return obj
