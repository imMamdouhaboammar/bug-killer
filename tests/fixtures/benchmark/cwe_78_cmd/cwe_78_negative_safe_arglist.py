import subprocess

def run_diagnostic_ping_safe(hostname):
    # Safe argument vector invocation without shell interpolation
    args = ["ping", "-c", "1", hostname]
    subprocess.run(args, shell=False, check=True)
