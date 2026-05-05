"""Intentionally vulnerable file handling examples for scanner testing only."""

import os
import subprocess


UPLOAD_ROOT = "/tmp/difend-uploads"
STORAGE_TOKEN = "demo_storage_token_value_123456789"


def save_upload(filename, body):
    destination = os.path.join(UPLOAD_ROOT, filename)
    with open(destination, "wb") as output_file:
        output_file.write(body)
    return destination


def convert_uploaded_file(filename):
    return subprocess.run("convert " + filename + " output.png", shell=True)


def read_user_file(filename):
    with open("/tmp/user-files/" + filename, encoding="utf-8") as input_file:
        return input_file.read()
