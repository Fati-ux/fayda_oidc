from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import time
import uuid
from urllib.parse import urlencode, urlparse

import frappe
import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe import _
from frappe.auth import LoginManager
from frappe.utils import cint, get_url
from jwt.algorithms import RSAAlgorithm

FLOW_LOGIN = "login"
FLOW_SIGNUP = "signup"
VALID_FLOWS = {FLOW_LOGIN, FLOW_SIGNUP}

DEFAULT_DISCOVERY_URL = "https://auth.fayda.et/.well-known/openid-configuration"
DEFAULT_REDIRECT_PATH = "/lms"
OIDC_STATE_TTL_SECONDS = 10 * 60
HTTP_TIMEOUT_SECONDS = 30
STATE_CACHE_PREFIX = "fayda_oidc:state:"
METADATA_CACHE_KEY = "fayda_oidc:metadata"
JWKS_CACHE_KEY = "fayda_oidc:jwks"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def b64url(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_to_int(value: str) -> int:
	padded = value + "=" * (-len(value) % 4)
	return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def is_fayda_configured() -> bool:
	"""Return whether the minimum local credentials are present.

	This deliberately does not contact Fayda. It is used while rendering the login
	page, where a remote discovery failure should not break password login.
	"""
	return bool(
		frappe.conf.get("fayda_client_id")
		and frappe.conf.get("fayda_private_key_base64_jwk")
		and cint(frappe.conf.get("fayda_enabled", 1))
	)


def _get_oidc_metadata(force_refresh: bool = False) -> dict:
	if not force_refresh:
		cached = frappe.cache.get_value(METADATA_CACHE_KEY)
		if cached:
			return cached

	discovery_url = frappe.conf.get("fayda_discovery_url", DEFAULT_DISCOVERY_URL)
	_require_https_url(discovery_url, _("Fayda discovery URL"))

	try:
		response = requests.get(
			discovery_url,
			headers={"Accept": "application/json"},
			timeout=HTTP_TIMEOUT_SECONDS,
		)
		response.raise_for_status()
		metadata = response.json()
	except (requests.RequestException, ValueError):
		frappe.log_error(
			title="Fayda OIDC discovery failed",
			message=frappe.get_traceback(),
		)
		frappe.throw(_("SmartTutor could not connect to Fayda. Please try again later."))

	if not isinstance(metadata, dict):
		frappe.throw(_("Fayda returned invalid OpenID configuration."))

	frappe.cache.set_value(METADATA_CACHE_KEY, metadata, expires_in_sec=60 * 60)
	return metadata


def get_settings() -> dict:
	metadata = _get_oidc_metadata()

	settings = {
		"client_id": frappe.conf.get("fayda_client_id"),
		"redirect_uri": frappe.conf.get("fayda_redirect_uri") or get_url("/fayda-callback"),
		"authorization_endpoint": frappe.conf.get("fayda_authorization_endpoint")
		or metadata.get("authorization_endpoint"),
		"token_endpoint": frappe.conf.get("fayda_token_endpoint") or metadata.get("token_endpoint"),
		"userinfo_endpoint": frappe.conf.get("fayda_userinfo_endpoint")
		or metadata.get("userinfo_endpoint"),
		"issuer": frappe.conf.get("fayda_issuer") or metadata.get("issuer"),
		"jwks_uri": frappe.conf.get("fayda_jwks_uri") or metadata.get("jwks_uri"),
		"scope": frappe.conf.get("fayda_scope", "openid profile email phone"),
		"acr_values": frappe.conf.get("fayda_acr_values"),
		"claims": frappe.conf.get("fayda_claims"),
		"claims_locales": frappe.conf.get("fayda_claims_locales"),
		"prompt": frappe.conf.get("fayda_prompt"),
		"base64_jwk": frappe.conf.get("fayda_private_key_base64_jwk"),
	}

	missing = [
		key
		for key in (
			"client_id",
			"redirect_uri",
			"authorization_endpoint",
			"token_endpoint",
			"userinfo_endpoint",
			"issuer",
			"jwks_uri",
			"base64_jwk",
		)
		if not settings.get(key)
	]
	if missing:
		frappe.throw(
			_("Fayda OIDC is not fully configured. Missing: {0}").format(", ".join(missing))
		)

	for key in (
		"redirect_uri",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"issuer",
		"jwks_uri",
	):
		_require_https_url(settings[key], key.replace("_", " ").title())

	return settings


def _require_https_url(value: str, label: str) -> None:
	parsed = urlparse(value)
	allow_http = cint(frappe.conf.get("fayda_allow_insecure_http", 0))
	allowed_schemes = {"https", "http"} if allow_http else {"https"}
	if not parsed.netloc or parsed.scheme not in allowed_schemes:
		frappe.throw(_("{0} must be an HTTPS URL.").format(label))


def _decode_private_jwk(raw_value) -> dict:
	if isinstance(raw_value, dict):
		jwk = raw_value
	else:
		raw_value = str(raw_value or "").strip()
		try:
			if raw_value.startswith("{"):
				jwk = json.loads(raw_value)
			else:
				padded = raw_value + "=" * (-len(raw_value) % 4)
				jwk = json.loads(base64.urlsafe_b64decode(padded).decode())
		except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
			frappe.throw(_("The configured Fayda private JWK is invalid."))

	required_fields = {"kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"}
	if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or not required_fields.issubset(jwk):
		frappe.throw(_("The configured Fayda private JWK must be a complete RSA private key."))
	return jwk


def load_private_key_from_base64_jwk():
	jwk = _decode_private_jwk(frappe.conf.get("fayda_private_key_base64_jwk"))

	try:
		private_numbers = rsa.RSAPrivateNumbers(
			p=b64url_to_int(jwk["p"]),
			q=b64url_to_int(jwk["q"]),
			d=b64url_to_int(jwk["d"]),
			dmp1=b64url_to_int(jwk["dp"]),
			dmq1=b64url_to_int(jwk["dq"]),
			iqmp=b64url_to_int(jwk["qi"]),
			public_numbers=rsa.RSAPublicNumbers(
				e=b64url_to_int(jwk["e"]),
				n=b64url_to_int(jwk["n"]),
			),
		)
		private_key = private_numbers.private_key()
	except (ValueError, TypeError, binascii.Error):
		frappe.throw(_("The configured Fayda private JWK contains invalid RSA values."))

	return private_key, jwk.get("kid")


def create_client_assertion(settings: dict | None = None) -> str:
	settings = settings or get_settings()
	private_key, kid = load_private_key_from_base64_jwk()
	now = int(time.time())

	payload = {
		"iss": settings["client_id"],
		"sub": settings["client_id"],
		"aud": settings["token_endpoint"],
		"jti": str(uuid.uuid4()),
		"iat": now,
		"exp": now + 300,
	}

	headers = {"alg": "RS256", "typ": "JWT"}
	if kid:
		headers["kid"] = kid

	return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def _state_cache_key(state: str) -> str:
	return f"{STATE_CACHE_PREFIX}{hashlib.sha256(state.encode()).hexdigest()}"


def _safe_redirect(value: str | None, default: str | None = None) -> str:
	default = default or frappe.conf.get("fayda_redirect_after_login", DEFAULT_REDIRECT_PATH)
	if (
		not isinstance(default, str)
		or not default.startswith("/")
		or default.startswith("//")
		or "\\" in default
		or any(ord(char) < 32 for char in default)
	):
		default = DEFAULT_REDIRECT_PATH
	value = (value or "").strip()
	if not value:
		return default

	parsed = urlparse(value)
	if parsed.scheme or parsed.netloc:
		base = urlparse(get_url())
		if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc):
			return default
		value = parsed.path or "/"
		if parsed.query:
			value = f"{value}?{parsed.query}"

	if (
		not value.startswith("/")
		or value.startswith("//")
		or "\\" in value
		or any(ord(char) < 32 for char in value)
	):
		return default
	return value


def _normalize_flow(flow: str | None) -> str:
	return flow if flow in VALID_FLOWS else FLOW_LOGIN


def _signup_is_disabled() -> bool:
	return bool(cint(frappe.get_website_settings("disable_signup")))


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_authorize_url(
	flow: str = FLOW_LOGIN,
	redirect_to: str | None = None,
) -> str:
	if not cint(frappe.conf.get("fayda_enabled", 1)):
		frappe.throw(_("Fayda authentication is disabled."), frappe.PermissionError)
	flow = _normalize_flow(flow)
	if flow == FLOW_SIGNUP and _signup_is_disabled():
		frappe.throw(_("Account creation is currently disabled."), frappe.PermissionError)

	settings = get_settings()
	state = secrets.token_urlsafe(32)
	nonce = secrets.token_urlsafe(32)
	verifier = secrets.token_urlsafe(64)
	challenge = b64url(hashlib.sha256(verifier.encode()).digest())
	transaction = {
		"flow": flow,
		"nonce": nonce,
		"code_verifier": verifier,
		"redirect_uri": settings["redirect_uri"],
		"redirect_to": _safe_redirect(redirect_to),
		"created_at": int(time.time()),
	}
	frappe.cache.set_value(
		_state_cache_key(state),
		transaction,
		expires_in_sec=OIDC_STATE_TTL_SECONDS,
	)

	params = {
		"response_type": "code",
		"client_id": settings["client_id"],
		"redirect_uri": settings["redirect_uri"],
		"scope": settings["scope"],
		"state": state,
		"nonce": nonce,
		"code_challenge": challenge,
		"code_challenge_method": "S256",
	}

	for key in ("acr_values", "claims_locales", "prompt"):
		if settings.get(key):
			params[key] = settings[key]

	if settings.get("claims"):
		params["claims"] = (
			json.dumps(settings["claims"])
			if isinstance(settings["claims"], dict)
			else settings["claims"]
		)

	return settings["authorization_endpoint"] + "?" + urlencode(params)


def _consume_transaction(state: str | None) -> dict:
	if not state:
		frappe.throw(_("Missing Fayda state. Please start again from the login page."))

	cache_key = _state_cache_key(state)
	transaction = frappe.cache.get_value(cache_key)
	if transaction:
		frappe.cache.delete_value(cache_key)
	if not transaction:
		frappe.throw(_("The Fayda login request is invalid or expired. Please try again."))
	return transaction


def _exchange_code(code: str, transaction: dict, settings: dict) -> dict:
	data = {
		"grant_type": "authorization_code",
		"code": code,
		"redirect_uri": transaction["redirect_uri"],
		"client_id": settings["client_id"],
		"code_verifier": transaction["code_verifier"],
		"client_assertion_type": CLIENT_ASSERTION_TYPE,
		"client_assertion": create_client_assertion(settings),
	}

	try:
		response = requests.post(
			settings["token_endpoint"],
			data=data,
			headers={"Accept": "application/json"},
			timeout=HTTP_TIMEOUT_SECONDS,
		)
		response.raise_for_status()
		token_data = response.json()
	except (requests.RequestException, ValueError):
		frappe.log_error(
			title="Fayda token exchange failed",
			message=frappe.get_traceback(),
		)
		frappe.throw(_("Fayda could not complete authentication. Please try again."))

	if not isinstance(token_data, dict):
		frappe.throw(_("Fayda returned an invalid token response."))
	if not token_data.get("access_token") or not token_data.get("id_token"):
		frappe.throw(_("Fayda did not return the required OpenID tokens."))
	return token_data


def _get_jwks(settings: dict, force_refresh: bool = False) -> dict:
	if not force_refresh:
		cached = frappe.cache.get_value(JWKS_CACHE_KEY)
		if cached:
			return cached

	try:
		response = requests.get(
			settings["jwks_uri"],
			headers={"Accept": "application/json"},
			timeout=HTTP_TIMEOUT_SECONDS,
		)
		response.raise_for_status()
		jwks = response.json()
	except (requests.RequestException, ValueError):
		frappe.log_error(
			title="Fayda JWKS retrieval failed",
			message=frappe.get_traceback(),
		)
		frappe.throw(_("SmartTutor could not verify the Fayda response. Please try again."))

	if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
		frappe.throw(_("Fayda returned invalid signing keys."))

	frappe.cache.set_value(JWKS_CACHE_KEY, jwks, expires_in_sec=15 * 60)
	return jwks


def _find_signing_jwk(token: str, settings: dict) -> dict:
	try:
		header = jwt.get_unverified_header(token)
	except jwt.PyJWTError:
		frappe.throw(_("Fayda returned an invalid signed token."))

	if header.get("alg") != "RS256":
		frappe.throw(_("Fayda returned a token with an unsupported signing algorithm."))

	kid = header.get("kid")
	for force_refresh in (False, True):
		keys = _get_jwks(settings, force_refresh=force_refresh).get("keys", [])
		candidates = [
			key
			for key in keys
			if key.get("kty") == "RSA" and (not kid or key.get("kid") == kid)
		]
		if len(candidates) == 1:
			return candidates[0]

	frappe.throw(_("SmartTutor could not find the Fayda key used to sign the response."))


def _decode_signed_jwt(
	token: str,
	settings: dict,
	*,
	nonce: str | None = None,
	id_token: bool = False,
) -> dict:
	signing_jwk = _find_signing_jwk(token, settings)
	try:
		public_key = RSAAlgorithm.from_jwk(json.dumps(signing_jwk))
		unverified = jwt.decode(token, options={"verify_signature": False})
		options = {
			"require": ["sub"],
			"verify_aud": id_token or bool(unverified.get("aud")),
			"verify_iss": id_token or bool(unverified.get("iss")),
		}
		if id_token:
			options["require"] = ["sub", "iss", "aud", "exp", "iat"]

		claims = jwt.decode(
			token,
			public_key,
			algorithms=["RS256"],
			audience=settings["client_id"],
			issuer=settings["issuer"],
			leeway=cint(frappe.conf.get("fayda_clock_skew_seconds", 60)),
			options=options,
		)
	except (jwt.PyJWTError, ValueError, TypeError):
		frappe.log_error(
			title="Fayda signed token validation failed",
			message=frappe.get_traceback(),
		)
		frappe.throw(_("SmartTutor could not verify the Fayda identity response."))

	if nonce is not None:
		received_nonce = str(claims.get("nonce") or "")
		if not received_nonce or not secrets.compare_digest(received_nonce, nonce):
			frappe.throw(_("Fayda nonce validation failed. Please start again."))
	return claims


def _validate_id_token_binding(claims: dict, access_token: str, client_id: str) -> None:
	audience = claims.get("aud")
	if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != client_id:
		frappe.throw(_("Fayda authorized-party validation failed."))
	if claims.get("azp") and claims.get("azp") != client_id:
		frappe.throw(_("Fayda authorized-party validation failed."))

	if claims.get("at_hash"):
		expected = b64url(hashlib.sha256(access_token.encode()).digest()[:16])
		if not secrets.compare_digest(str(claims["at_hash"]), expected):
			frappe.throw(_("Fayda access-token validation failed."))


def _fetch_userinfo(access_token: str, settings: dict) -> dict:
	method = str(frappe.conf.get("fayda_userinfo_method", "GET")).upper()
	request_method = requests.post if method == "POST" else requests.get

	try:
		response = request_method(
			settings["userinfo_endpoint"],
			headers={
				"Authorization": f"Bearer {access_token}",
				"Accept": "application/jwt, application/json",
			},
			timeout=HTTP_TIMEOUT_SECONDS,
		)
		response.raise_for_status()
	except requests.RequestException:
		frappe.log_error(
			title="Fayda userinfo request failed",
			message=frappe.get_traceback(),
		)
		frappe.throw(_("SmartTutor could not retrieve your verified Fayda profile."))

	body = response.text.strip()
	if body.count(".") == 2:
		return _decode_signed_jwt(body, settings)
	if body.count(".") == 4:
		frappe.throw(
			_("Encrypted Fayda userinfo is not enabled for this SmartTutor integration.")
		)

	try:
		profile = response.json()
	except ValueError:
		frappe.throw(_("Fayda returned an invalid user profile."))
	if not isinstance(profile, dict):
		frappe.throw(_("Fayda returned an invalid user profile."))
	return profile


@frappe.whitelist(allow_guest=True, methods=["GET"])
def callback(
	code: str | None = None,
	state: str | None = None,
	error: str | None = None,
	error_description: str | None = None,
):
	transaction = _consume_transaction(state)

	if error:
		description = (error_description or error).strip()[:240]
		frappe.throw(_("Fayda authentication was not completed: {0}").format(description))
	if not code:
		frappe.throw(_("Missing Fayda authorization code."))

	settings = get_settings()
	token_data = _exchange_code(code, transaction, settings)
	id_claims = _decode_signed_jwt(
		token_data["id_token"],
		settings,
		nonce=transaction["nonce"],
		id_token=True,
	)
	_validate_id_token_binding(id_claims, token_data["access_token"], settings["client_id"])
	userinfo = _fetch_userinfo(token_data["access_token"], settings)
	if userinfo.get("sub") != id_claims.get("sub"):
		frappe.throw(_("Fayda returned inconsistent identity information."))

	profile = {**id_claims, **userinfo}
	user = login_or_create_user(profile, transaction["flow"])

	# OAuth callbacks use GET, so commit the link/account creation explicitly.
	frappe.db.commit()
	frappe.local.login_manager = LoginManager()
	frappe.local.login_manager.login_as(user)

	redirect_location = _safe_redirect(transaction.get("redirect_to"))
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_location
	frappe.local.flags.redirect_location = redirect_location
	raise frappe.Redirect


def _claim_is_true(value) -> bool:
	return value is True or value == 1 or str(value).lower() == "true"


def _trusted_email(profile: dict) -> str | None:
	email = str(profile.get("email") or "").strip().lower()
	if not email:
		return None
	if _claim_is_true(profile.get("email_verified")) or cint(
		frappe.conf.get("fayda_trust_unverified_email", 0)
	):
		return email
	return None


def _fallback_email(fayda_sub: str) -> str:
	domain = str(frappe.conf.get("fayda_email_domain", "fayda.local")).strip().lower()
	if not re.fullmatch(r"[a-z0-9.-]+", domain):
		frappe.throw(_("fayda_email_domain contains invalid characters."))
	digest = hashlib.sha256(fayda_sub.encode()).hexdigest()[:32]
	return f"fayda-{digest}@{domain}"


def _ensure_user_can_be_linked(user: str, fayda_sub: str) -> None:
	enabled, user_type, linked_sub = frappe.db.get_value(
		"User",
		user,
		["enabled", "user_type", "custom_fayda_sub"],
	)
	if not cint(enabled):
		frappe.throw(_("This SmartTutor account is disabled."), frappe.PermissionError)
	if linked_sub and not secrets.compare_digest(str(linked_sub), fayda_sub):
		frappe.throw(_("This SmartTutor account is already linked to another Fayda identity."))
	if user_type == "System User" and not linked_sub and not cint(
		frappe.conf.get("fayda_allow_system_user_linking", 0)
	):
		frappe.throw(
			_(
				"Fayda cannot be linked automatically to a staff account. "
				"Ask an administrator to link it."
			),
			frappe.PermissionError,
		)


def _add_default_roles(user: str) -> None:
	default_roles = frappe.conf.get("fayda_default_roles", ["LMS Student"])
	if isinstance(default_roles, str):
		default_roles = [role.strip() for role in default_roles.split(",") if role.strip()]

	user_doc = frappe.get_doc("User", user)
	for role in default_roles:
		if frappe.db.exists("Role", role):
			user_doc.add_roles(role)


def _new_fayda_user(profile: dict, fayda_sub: str, trusted_email: str | None) -> str:
	email = trusted_email or _fallback_email(fayda_sub)
	first_name = (
		str(profile.get("given_name") or profile.get("name") or _("Fayda User")).strip()
		or _("Fayda User")
	)
	last_name = str(profile.get("family_name") or "").strip()
	phone = str(profile.get("phone_number") or profile.get("phone") or "").strip()

	doc = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": first_name,
			"last_name": last_name,
			"enabled": 1,
			"send_welcome_email": 0,
			"new_password": frappe.generate_hash(length=40),
			"user_type": "Website User",
			"mobile_no": phone,
			"custom_fayda_sub": fayda_sub,
		}
	)
	doc.flags.ignore_permissions = True
	doc.flags.no_welcome_mail = True
	doc.insert(ignore_permissions=True)

	_add_default_roles(doc.name)

	return doc.name


def login_or_create_user(profile: dict, flow: str = FLOW_SIGNUP) -> str:
	flow = _normalize_flow(flow)
	fayda_sub = str(profile.get("sub") or "").strip()
	if not fayda_sub:
		frappe.throw(_("Fayda userinfo is missing the subject identifier."))

	trusted_email = _trusted_email(profile)
	user = frappe.db.get_value("User", {"custom_fayda_sub": fayda_sub}, "name")

	if not user and trusted_email:
		user = frappe.db.get_value("User", {"email": trusted_email}, "name")

	if not user and flow == FLOW_LOGIN:
		frappe.throw(
			_(
				"No SmartTutor account is linked to this Fayda identity. "
				"Choose “Create account with Fayda” first."
			),
			frappe.DoesNotExistError,
		)

	if not user:
		if _signup_is_disabled():
			frappe.throw(_("Account creation is currently disabled."), frappe.PermissionError)
		user = _new_fayda_user(profile, fayda_sub, trusted_email)
	else:
		_ensure_user_can_be_linked(user, fayda_sub)
		if not frappe.db.get_value("User", user, "custom_fayda_sub"):
			frappe.db.set_value(
				"User",
				user,
				"custom_fayda_sub",
				fayda_sub,
				update_modified=False,
			)
		if flow == FLOW_SIGNUP and frappe.db.get_value("User", user, "user_type") == "Website User":
			_add_default_roles(user)

	phone = str(profile.get("phone_number") or profile.get("phone") or "").strip()
	if phone and not frappe.db.get_value("User", user, "mobile_no"):
		frappe.db.set_value("User", user, "mobile_no", phone, update_modified=False)

	return user
