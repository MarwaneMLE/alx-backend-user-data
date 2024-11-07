#!/usr/bin/env python3
""" Hash and validate passwords using bcrypt. """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashes the password and returns it as a byte string. """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates if the provided password matches the hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
