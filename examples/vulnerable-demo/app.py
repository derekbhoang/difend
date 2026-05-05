"""Intentionally vulnerable demo code for scanner testing only."""

import os
import pickle
import subprocess


DEBUG = True
APP_SECRET = "demo_app_secret_value_123456789"


def evaluate_user_expression(user_expression):
    return eval(user_expression)


def run_support_command(command):
    return subprocess.run(command, shell=True, check=False)


def execute_admin_script(script_body):
    exec(script_body)
    return "script executed"


def load_session_blob(raw_blob):
    return pickle.loads(raw_blob)


def read_report_file(report_name):
    path = "/tmp/difend-reports/" + report_name
    with open(path, encoding="utf-8") as report_file:
        return report_file.read()


def delete_cache_file(filename):
    os.remove("/tmp/difend-cache/" + filename)
