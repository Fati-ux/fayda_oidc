import json
import time
from unittest import TestCase
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from fayda_oidc import api


class TestFaydaOidcHelpers(TestCase):
	def test_safe_redirect_accepts_local_path(self):
		self.assertEqual(
			api._safe_redirect("/lms/courses?topic=math", default="/lms"),
			"/lms/courses?topic=math",
		)

	def test_safe_redirect_rejects_external_and_protocol_relative_urls(self):
		self.assertEqual(api._safe_redirect("https://example.com/phish", default="/lms"), "/lms")
		self.assertEqual(api._safe_redirect("//example.com/phish", default="/lms"), "/lms")
		self.assertEqual(api._safe_redirect("javascript:alert(1)", default="/lms"), "/lms")

	def test_fallback_email_does_not_expose_subject(self):
		with patch.object(api.frappe, "conf", {"fayda_email_domain": "fayda.local"}):
			email = api._fallback_email("private-fayda-subject")

		self.assertNotIn("private-fayda-subject", email)
		self.assertTrue(email.endswith("@fayda.local"))

	def test_id_token_signature_audience_issuer_and_nonce_are_verified(self):
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
		public_jwk["kid"] = "test-key"
		now = int(time.time())
		settings = {
			"client_id": "smart-tutor",
			"issuer": "https://issuer.example",
			"jwks_uri": "https://issuer.example/.well-known/jwks.json",
		}
		token = jwt.encode(
			{
				"sub": "fayda-user",
				"iss": settings["issuer"],
				"aud": settings["client_id"],
				"iat": now,
				"exp": now + 300,
				"nonce": "expected-nonce",
			},
			private_key,
			algorithm="RS256",
			headers={"kid": "test-key"},
		)

		with (
			patch.object(api, "_get_jwks", return_value={"keys": [public_jwk]}),
			patch.object(api.frappe, "conf", {"fayda_clock_skew_seconds": 60}),
		):
			claims = api._decode_signed_jwt(
				token,
				settings,
				nonce="expected-nonce",
				id_token=True,
			)

		self.assertEqual(claims["sub"], "fayda-user")
