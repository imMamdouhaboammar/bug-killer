import os

def run_diagnostic_ping(hostname):
    # Vulnerable Command Injection via unquoted shell command execution
    cmd = "ping -c 1 " + hostname
    os.system(cmd)
