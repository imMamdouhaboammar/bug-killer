# Safe: subprocess uses argument list without shell=True
import subprocess
import ipaddress

def safe_ping(host_str):
    ip = ipaddress.ip_address(host_str)
    subprocess.run(["ping", "-c", "1", str(ip)], shell=False, check=True)
