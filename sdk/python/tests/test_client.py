import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lanyard.client import _grant_proof


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class GrantProofTests(unittest.TestCase):
    def test_proof_is_bound_to_method_and_url_and_omits_access_token_hash(self):
        seed = bytes(range(32))
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        proof = _grant_proof(seed, "POST", "https://controlplane.example/grant")
        header_part, claims_part, signature_part = proof.split(".")
        header = json.loads(_decode(header_part))
        claims = json.loads(_decode(claims_part))
        expected_key = base64.urlsafe_b64encode(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).rstrip(b"=").decode("ascii")

        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["typ"], "dpop+jwt")
        self.assertEqual(header["jwk"]["x"], expected_key)
        self.assertEqual(claims["htm"], "POST")
        self.assertEqual(claims["htu"], "https://controlplane.example/grant")
        self.assertNotIn("ath", claims)
        private_key.public_key().verify(
            _decode(signature_part), f"{header_part}.{claims_part}".encode("ascii"))

    def test_rejects_non_seed_sized_key(self):
        with self.assertRaises(ValueError):
            _grant_proof(b"short", "POST", "https://controlplane.example/grant")


if __name__ == "__main__":
    unittest.main()