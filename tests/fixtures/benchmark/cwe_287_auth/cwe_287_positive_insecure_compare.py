def authenticate_signature(user_token, secret_expected_token):
    # Vulnerable non-constant-time string comparison susceptible to timing analysis
    if user_token == secret_expected_token:
        return True
    return False
