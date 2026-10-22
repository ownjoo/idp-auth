import base64
import unittest
from typing import ClassVar

from idp_auth.factors.totp import Totp, hotp

SHA1_SECRET = b'12345678901234567890'
SHA256_SECRET = b'12345678901234567890123456789012'
SHA512_SECRET = b'1234567890' * 6 + b'1234'


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode()


class TestHotp(unittest.TestCase):
    def test_rfc4226_vectors(self):
        expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
        for counter, code in enumerate(expected):
            self.assertEqual(hotp(SHA1_SECRET, counter), code)


class TestTotp(unittest.TestCase):
    # RFC 6238 Appendix B
    VECTORS: ClassVar = [
        (59, '94287082', '46119246', '90693936'),
        (1111111109, '07081804', '68084774', '25091201'),
        (1111111111, '14050471', '67062674', '99943326'),
        (1234567890, '89005924', '91819424', '93441116'),
        (2000000000, '69279037', '90698825', '38618901'),
        (20000000000, '65353130', '77737706', '47863826'),
    ]

    def test_rfc6238_sha1(self):
        totp = Totp(b32(SHA1_SECRET), digits=8)
        for t, sha1, _, _ in self.VECTORS:
            self.assertEqual(totp.at(t), sha1)

    def test_rfc6238_sha256(self):
        totp = Totp(b32(SHA256_SECRET), digits=8, algorithm='SHA256')
        for t, _, sha256, _ in self.VECTORS:
            self.assertEqual(totp.at(t), sha256)

    def test_rfc6238_sha512(self):
        totp = Totp(b32(SHA512_SECRET), digits=8, algorithm='SHA512')
        for t, _, _, sha512 in self.VECTORS:
            self.assertEqual(totp.at(t), sha512)

    def test_default_six_digits(self):
        self.assertEqual(Totp(b32(SHA1_SECRET)).at(59), '287082')

    def test_secret_normalisation(self):
        # IdPs display secrets lowercased, grouped with spaces, and without base32 padding
        messy = ' '.join(b32(SHA1_SECRET).lower().rstrip('=')[i : i + 4] for i in range(0, 32, 4))
        self.assertEqual(Totp(messy).at(59), '287082')

    def test_now_uses_injected_clock(self):
        self.assertEqual(Totp(b32(SHA1_SECRET), clock=lambda: 59.0).now(), '287082')

    def test_verify_with_window(self):
        totp = Totp(b32(SHA1_SECRET))
        code = totp.at(59)
        self.assertTrue(totp.verify(code, t=59 + 30, window=1))
        self.assertFalse(totp.verify(code, t=59 + 90, window=1))

    def test_from_uri(self):
        uri = (
            'otpauth://totp/Example:svc-account@example.com'
            f'?secret={b32(SHA256_SECRET)}&issuer=Example&algorithm=SHA256&digits=8&period=30'
        )
        totp = Totp.from_uri(uri)
        self.assertEqual(totp.at(59), '46119246')
        self.assertEqual(totp.issuer, 'Example')
        self.assertEqual(totp.account, 'svc-account@example.com')

    def test_from_uri_rejects_hotp(self):
        with self.assertRaises(ValueError):
            Totp.from_uri('otpauth://hotp/x?secret=AAAA&counter=0')

    def test_to_uri_round_trip(self):
        totp = Totp(b32(SHA1_SECRET), issuer='Acme', account='svc')
        self.assertEqual(Totp.from_uri(totp.to_uri()).at(59), '287082')


if __name__ == '__main__':
    unittest.main()
