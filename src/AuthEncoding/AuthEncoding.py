##############################################################################
#
# Copyright (c) 2002, 2015 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################

import binascii
from binascii import b2a_base64, a2b_base64
from hashlib import sha1 as sha
from hashlib import sha256
from os import getpid
import time


# Use the system PRNG if possible
import random
try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    using_sysrandom = False


def _reseed():
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(sha256(
            f"{random.getstate()}{time.time()}{getpid()}"
        ).digest())


def _choice(c):
    _reseed()
    return random.choice(c)


def _randrange(r):
    _reseed()
    return random.randrange(r)


def binary(arg):
    """Convert `arg` to latin-1 encoded bytes."""
    if not isinstance(arg, bytes):
        arg = arg.encode("latin-1")
    return arg


def text(arg):
    """Convert `arg` to text assuming it to be latin-1 encoded."""
    if isinstance(arg, bytes):
        arg = arg.decode('ascii', 'replace')
    return arg


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0


class PasswordEncryptionScheme:  # An Interface

    def encrypt(pw):
        """
        Encrypt the provided plain text password.
        """

    def validate(reference, attempt):
        """
        Validate the provided password string.  Reference is the
        correct password, which may be encrypted; attempt is clear text
        password attempt.
        """


_schemes = []


def registerScheme(id, s):
    '''
    Registers an LDAP password encoding scheme.
    '''
    _schemes.append((id, '{%s}' % id, s))


def listSchemes():
    return [id for id, prefix, scheme in _schemes]


class SSHADigestScheme:
    '''
    SSHA is a modification of the SHA digest scheme with a salt
    starting at byte 20 of the base64-encoded string.
    '''
    # Source: http://developer.netscape.com/docs/technote/ldap/pass_sha.html

    def generate_salt(self):
        # Salt can be any length, but not more than about 37 characters
        # because of limitations of the binascii module.
        # 7 is what Netscape's example used and should be enough.
        # All 256 characters are available.
        salt = b''
        for n in range(7):
            salt += bytes((_randrange(256),))
        return salt

    def encrypt(self, pw):
        return self._encrypt_with_salt(pw, self.generate_salt())

    def validate(self, reference, attempt):
        try:
            ref = a2b_base64(reference)
        except binascii.Error:
            # Not valid base64.
            return 0
        salt = ref[20:]
        compare = self._encrypt_with_salt(attempt, salt)
        return constant_time_compare(compare, reference)

    def _encrypt_with_salt(self, pw, salt):
        pw = binary(pw)
        return b2a_base64(sha(pw + salt).digest() + salt)[:-1]


registerScheme('SSHA', SSHADigestScheme())


class SHADigestScheme:

    def encrypt(self, pw):
        return self._encrypt(pw)

    def validate(self, reference, attempt):
        compare = self._encrypt(attempt)
        return constant_time_compare(compare, reference)

    def _encrypt(self, pw):
        pw = binary(pw)
        return b2a_base64(sha(pw).digest())[:-1]


registerScheme('SHA', SHADigestScheme())


class SHA256DigestScheme:

    def encrypt(self, pw):
        return binary(sha256(binary(pw)).hexdigest())

    def validate(self, reference, attempt):
        a = self.encrypt(attempt)
        return constant_time_compare(a, reference)


registerScheme('SHA256', SHA256DigestScheme())


# Bcrypt support may not have been requested at installation time
# - installed via the 'bcrypt' extra
try:
    import bcrypt
except ImportError:
    bcrypt = None


class BCRYPTHashingScheme:
    """A BCRYPT hashing scheme."""

    @staticmethod
    def _ensure_bytes(pw, encoding='utf-8'):
        """Ensures the given password `pw` is returned as bytes."""
        if isinstance(pw, str):
            pw = pw.encode(encoding)
        return pw

    def encrypt(self, pw):
        return bcrypt.hashpw(self._ensure_bytes(pw), bcrypt.gensalt())

    def validate(self, reference, attempt):
        try:
            return bcrypt.checkpw(self._ensure_bytes(attempt), reference)
        except ValueError:
            # Usually due to an invalid salt
            return False


if bcrypt is not None:
    registerScheme('BCRYPT', BCRYPTHashingScheme())


# Bogosity on various platforms due to ITAR restrictions
try:
    from crypt import crypt
except ImportError:
    crypt = None

if crypt is not None:

    class CryptDigestScheme:

        def generate_salt(self):
            choices = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789./")
            return _choice(choices) + _choice(choices)

        def encrypt(self, pw):
            return binary(
                crypt(self._recode_password(pw), self.generate_salt()))

        def validate(self, reference, attempt):
            attempt = self._recode_password(attempt)
            a = binary(crypt(attempt, reference[:2].decode('ascii')))
            return constant_time_compare(a, reference)

        def _recode_password(self, pw):
            # crypt requires `str`:
            return text(pw)

    registerScheme('CRYPT', CryptDigestScheme())


class MySQLDigestScheme:

    def encrypt(self, pw):
        pw = text(pw)
        nr = int(1345345333)
        add = 7
        nr2 = int(0x12345671)
        for i in pw:
            if i == ' ' or i == '\t':
                continue
            nr ^= (((nr & 63) + add) * ord(i)) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            add += ord(i)
        r0 = nr & ((int(1) << 31) - int(1))
        r1 = nr2 & ((int(1) << 31) - int(1))
        return ("{:08x}{:08x}".format(r0, r1)).encode('ascii')

    def validate(self, reference, attempt):
        a = self.encrypt(attempt)
        return constant_time_compare(a, reference)


registerScheme('MYSQL', MySQLDigestScheme())


def pw_validate(reference, attempt):
    """Validate the provided password string, which uses LDAP-style encoding
    notation.  Reference is the correct password, attempt is clear text
    password attempt."""
    reference = binary(reference)
    for id, prefix, scheme in _schemes:
        lp = len(prefix)
        if reference[:lp] == binary(prefix):
            return scheme.validate(reference[lp:], attempt)
    # Assume cleartext.
    return constant_time_compare(reference, binary(attempt))


def is_encrypted(pw):
    pw = binary(pw)
    for id, prefix, scheme in _schemes:
        lp = len(prefix)
        if pw[:lp] == binary(prefix):
            return 1
    return 0


def pw_encrypt(pw, encoding='SSHA'):
    """Encrypt the provided plain text password using the encoding if provided
    and return it in an LDAP-style representation."""
    encoding = text(encoding)
    for id, prefix, scheme in _schemes:
        if encoding == id:
            return binary(prefix) + scheme.encrypt(pw)
    raise ValueError('Not supported: %s' % encoding)


pw_encode = pw_encrypt  # backward compatibility
