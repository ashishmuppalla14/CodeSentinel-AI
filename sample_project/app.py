"""SYNTHETIC DEMO FILE - intentionally vulnerable, never deploy. Contains fake credentials."""
import os
import pickle
import sqlite3
import subprocess
import sys
import yaml
from flask import Flask, request

app = Flask(__name__)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"   # fake key from AWS documentation
DB_PASSWORD = "S3cr3tP@ssw0rd!"              # fake demo password


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str(obj) + str(cfg)


@app.route("/report")
def report():
    pass


@app.route("/export")
def export():
    return {"message": "TODO"}


def run_job(cmd):
    return subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
