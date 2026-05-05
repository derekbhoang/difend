"""Intentionally weak crypto examples for agent review context."""

import hashlib
import random


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def make_reset_token():
    return str(random.randint(100000, 999999))


def compare_token(expected, provided):
    return expected == provided
