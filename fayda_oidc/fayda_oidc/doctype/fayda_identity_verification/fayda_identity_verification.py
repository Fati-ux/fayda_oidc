from __future__ import annotations

import hashlib
import hmac
import json
import re
from urllib.parse import urlencode

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import getdate, now_datetime

DOCTYPE = "Fayda Identity Verification"
STATUS_DRAFT = "Draft"
STATUS_PENDING = "Pending OTP"
STATUS_VERIFIED = "Verified"
STATUS_FAILED = "Failed"

PROFILE_FIELDS = (
	"name",
	"given_name",
	"family_name",
	"email",
	"phone_number",
	"phone",
	"gender",
	"birthdate",
	"address",
	"locale",
)


def _normalize_identifier(value: str) -> str:
	return re.sub(r"[^A-Za-z0-9]", "", str(value or "")).upper()


def _validate_identifier(value: str) -> str:
	normalized = _normalize_identifier(value)
	if not re.fullmatch(r"[A-Z0-9]{6,32}", normalized):
		frappe.throw(
			_("Enter a valid Fayda Alias Number (FAN) or Fayda Identification Number (FIN).")
		)
	return normalized


def _mask_identifier(value: str) -> str:
	normalized = _normalize_identifier(value)
	if len(normalized) <= 4:
		return "*" * len(normalized)
	return f"{'*' * (len(normalized) - 4)}{normalized[-4:]}"


def _identifier_fingerprint(value: str) -> str:
	encryption_key = str(frappe.conf.get("encryption_key") or "")
	if not encryption_key:
		frappe.throw(_("The site encryption key is required for Fayda verification."))
	return hmac.new(
		encryption_key.encode(),
		_normalize_identifier(value).encode(),
		hashlib.sha256,
	).hexdigest()


def _safe_date(value):
	if not value:
		return None
	try:
		return getdate(value)
	except (TypeError, ValueError):
		return None


def _safe_profile(profile: dict) -> dict:
	return {key: profile.get(key) for key in PROFILE_FIELDS if profile.get(key) is not None}


class FaydaIdentityVerification(Document):
	def validate(self):
		if not self.status:
			self.status = STATUS_DRAFT
		if self.status not in {STATUS_DRAFT, STATUS_PENDING, STATUS_VERIFIED, STATUS_FAILED}:
			frappe.throw(_("Invalid Fayda verification status."))


def _get_admin_doc(name: str) -> FaydaIdentityVerification:
	frappe.only_for("System Manager")
	doc = frappe.get_doc(DOCTYPE, name)
	doc.check_permission("write")
	return doc


@frappe.whitelist()
def start_verification(name: str) -> str:
	"""Start hosted Fayda OTP authentication for an administrator-selected User."""
	doc = _get_admin_doc(name)
	fan = doc.get_password("fan", raise_exception=False)
	if not fan:
		frappe.throw(_("Enter the resident's FAN or FIN before starting verification."))

	_validate_identifier(fan)
	doc.status = STATUS_PENDING
	doc.fan_masked = _mask_identifier(fan)
	doc.initiated_by = frappe.session.user
	doc.initiated_at = now_datetime()
	doc.last_error = ""
	doc.save()

	redirect_to = f"/app/fayda-identity-verification/{doc.name}"
	return "/fayda-login?" + urlencode(
		{
			"flow": "verify",
			"verification": doc.name,
			"redirect_to": redirect_to,
		}
	)


def _fail(doc: FaydaIdentityVerification, message: str) -> FaydaIdentityVerification:
	doc.status = STATUS_FAILED
	doc.last_error = message
	doc.fan = ""
	doc.save(ignore_permissions=True)
	return doc


def _ensure_unique_identity(doc: FaydaIdentityVerification, fayda_sub: str) -> str | None:
	existing_user = frappe.db.get_value("User", {"custom_fayda_sub": fayda_sub}, "name")
	if existing_user and existing_user != doc.user:
		return _("This Fayda identity is already linked to another User.")

	existing_verification = frappe.db.get_value(
		DOCTYPE,
		{"fayda_sub": fayda_sub, "status": STATUS_VERIFIED},
		["name", "user"],
		as_dict=True,
	)
	if (
		existing_verification
		and existing_verification.name != doc.name
		and existing_verification.user != doc.user
	):
		return _("This Fayda identity was already verified for another User.")
	return None


def _sync_user(doc: FaydaIdentityVerification, profile: dict) -> None:
	user = frappe.get_doc("User", doc.user)
	fayda_sub = str(profile.get("sub") or doc.fayda_sub or "").strip()
	if not fayda_sub:
		frappe.throw(_("Fayda did not return a subject identifier."))

	duplicate_error = _ensure_unique_identity(doc, fayda_sub)
	if duplicate_error:
		frappe.throw(duplicate_error)

	field_values = {
		"first_name": profile.get("given_name"),
		"last_name": profile.get("family_name"),
		"mobile_no": profile.get("phone_number") or profile.get("phone"),
		"gender": profile.get("gender"),
		"birth_date": _safe_date(profile.get("birthdate")),
		"custom_fayda_sub": fayda_sub,
		"custom_fayda_verified": 1,
		"custom_fayda_verified_at": doc.verified_at,
		"custom_fayda_verification": doc.name,
		"custom_fayda_verified_name": profile.get("name"),
		"custom_fayda_verified_email": profile.get("email"),
		"custom_fayda_verified_phone": profile.get("phone_number") or profile.get("phone"),
	}

	for fieldname, value in field_values.items():
		if value not in (None, "") and user.meta.has_field(fieldname):
			user.set(fieldname, value)

	user.flags.ignore_permissions = True
	user.save(ignore_permissions=True)
	doc.last_synced_at = now_datetime()


def complete_verification(name: str, profile: dict) -> FaydaIdentityVerification:
	"""Complete a pending record using signature-validated Fayda userinfo claims."""
	doc = frappe.get_doc(DOCTYPE, name)
	if doc.status != STATUS_PENDING:
		return _fail(doc, _("This verification is no longer pending."))

	fan = doc.get_password("fan", raise_exception=False)
	if not fan:
		return _fail(doc, _("The FAN or FIN entered for this verification is unavailable."))

	returned_identifier = str(profile.get("individual_id") or "").strip()
	if not returned_identifier:
		return _fail(
			doc,
			_(
				"Fayda did not return the individual_id claim. Ask Fayda to enable this "
				"claim for the SmartTutor relying-party client."
			),
		)

	expected_identifier = _validate_identifier(fan)
	actual_identifier = _normalize_identifier(returned_identifier)
	if not actual_identifier or not hmac.compare_digest(expected_identifier, actual_identifier):
		return _fail(doc, _("The verified Fayda identity does not match the entered FAN or FIN."))

	fayda_sub = str(profile.get("sub") or "").strip()
	if not fayda_sub:
		return _fail(doc, _("Fayda did not return a subject identifier."))

	duplicate_error = _ensure_unique_identity(doc, fayda_sub)
	if duplicate_error:
		return _fail(doc, duplicate_error)

	safe_profile = _safe_profile(profile)
	doc.status = STATUS_VERIFIED
	doc.fan_fingerprint = _identifier_fingerprint(fan)
	doc.fan_masked = _mask_identifier(fan)
	doc.fan = ""
	doc.fayda_sub = fayda_sub
	doc.verified_name = profile.get("name")
	doc.verified_given_name = profile.get("given_name")
	doc.verified_family_name = profile.get("family_name")
	doc.verified_email = profile.get("email")
	doc.verified_phone = profile.get("phone_number") or profile.get("phone")
	doc.verified_gender = profile.get("gender")
	doc.verified_birthdate = _safe_date(profile.get("birthdate"))
	doc.verified_address = json.dumps(profile.get("address"), ensure_ascii=False, default=str)
	doc.verified_locale = profile.get("locale")
	doc.verified_acr = profile.get("acr")
	doc.verified_at = now_datetime()
	doc.verified_claims = json.dumps(safe_profile, ensure_ascii=False, indent=2, default=str)
	doc.last_error = ""

	try:
		_sync_user(doc, profile)
	except (frappe.ValidationError, frappe.PermissionError, frappe.DuplicateEntryError) as exc:
		return _fail(doc, _("Fayda was verified, but User synchronization failed: {0}").format(exc))

	doc.save(ignore_permissions=True)
	return doc


@frappe.whitelist()
def sync_to_user(name: str) -> None:
	doc = _get_admin_doc(name)
	if doc.status != STATUS_VERIFIED or not doc.fayda_sub:
		frappe.throw(_("Only a verified Fayda identity can be synchronized."))

	profile = json.loads(doc.verified_claims or "{}")
	profile["sub"] = doc.fayda_sub
	_sync_user(doc, profile)
	doc.save()

