# Vulnerable: user input reaches os.system shell execution
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    cmd = "ping -c 1 " + host
    os.system(cmd)
    return "ok"
