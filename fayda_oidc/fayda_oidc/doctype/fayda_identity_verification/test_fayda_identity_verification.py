from unittest import TestCase
from unittest.mock import patch

from fayda_oidc.fayda_oidc.doctype.fayda_identity_verification import (
	fayda_identity_verification as verification,
)


class TestFaydaIdentityVerificationHelpers(TestCase):
	def test_identifier_normalization(self):
		self.assertEqual(verification._normalize_identifier("1234-5678 9012"), "123456789012")

	def test_masking_keeps_only_last_four_characters(self):
		self.assertEqual(verification._mask_identifier("123456789012"), "********9012")

	def test_fingerprint_is_keyed(self):
		with patch.object(verification.frappe, "conf", {"encryption_key": "site-secret"}):
			first = verification._identifier_fingerprint("123456789012")
			second = verification._identifier_fingerprint("1234-5678-9012")

		self.assertEqual(first, second)
		self.assertNotEqual(first, verification.hashlib.sha256(b"123456789012").hexdigest())
