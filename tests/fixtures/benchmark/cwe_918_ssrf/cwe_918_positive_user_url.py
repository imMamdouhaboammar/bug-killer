import urllib.request

def dispatch_webhook(target_url):
    # Vulnerable Server-Side Request Forgery (SSRF) fetching unvalidated URL
    req = urllib.request.Request(target_url, headers={"User-Agent": "Notifier/1.0"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read()
