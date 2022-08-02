# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

crypto_auth_BYTES: int = lib.crypto_auth_bytes()
crypto_auth_KEYBYTES: int = lib.crypto_auth_keybytes()

def crypto_auth(message: bytes, key: bytes) -> bytes:
    """
    Hashes and returns the message ``message`` with the key ``key``.

    :param message: bytes
    :param key: bytes
    :rtype: bytes
    """
    digest = ffi.new("unsigned char[]", crypto_auth_BYTES)
    rc = lib.crypto_auth(digest, message, len(message), key)
    ensure(rc == 0, "Unexpected library error", raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_auth_BYTES)[:]

def crypto_auth_verify(tag: bytes, message: bytes, key: bytes) -> bytes:
    """
    Verifies that the hash ``tag`` corresponds to ``message`` with the key ``key``.

    :param tag: bytes
    :param message: bytes
    :param key: bytes
    :rtype: bytes
    """
    rc = lib.crypto_auth(tag, message, len(message), key)
    ensure(rc == 0, "Invalid tag", raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_auth_BYTES)[:]

def crypto_auth_keygen(message: bytes, key: bytes) -> bytes:
    """
    Creates and returns a key for use with the crypto_auth api.

    :rtype: bytes
    """
    key = ffi.new("unsigned char[]", crypto_auth_KEYBYTES)
    rc = lib.crypto_auth_keygen(key)
    ensure(rc == 0, "Unexpected library error", raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_auth_KEYBYTES)[:]
