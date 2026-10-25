import urllib.parse
import urllib.request

ALLOWED_DESTINATIONS = {"api.trusted-partner.com", "hooks.payments.org"}

def dispatch_webhook_safe(target_url):
    # Safe SSRF mitigation: strict scheme and domain allowlist validation
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme != "https":
        raise ValueError("Only secure HTTPS destinations are allowed")
    if parsed.hostname not in ALLOWED_DESTINATIONS:
        raise ValueError("Host is not present in trusted destination allowlist")
    
    req = urllib.request.Request(target_url, headers={"User-Agent": "Notifier/1.0"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read()
