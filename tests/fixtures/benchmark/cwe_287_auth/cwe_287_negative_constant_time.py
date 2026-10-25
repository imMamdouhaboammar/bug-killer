import hmac

def authenticate_signature_safe(user_token, secret_expected_token):
    # Constant-time comparison mitigating timing side channels
    return hmac.compare_digest(user_token, secret_expected_token)
