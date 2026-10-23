from __future__ import annotations

from html import escape
from urllib.parse import urlencode

import frappe
from frappe import _
from frappe.utils import cint

from fayda_oidc.api import (
	DEFAULT_REDIRECT_PATH,
	FLOW_LOGIN,
	FLOW_SIGNUP,
	_safe_redirect,
	is_fayda_configured,
)


def _flow_url(flow: str, redirect_to: str) -> str:
	return "/fayda-login?" + urlencode({"flow": flow, "redirect_to": redirect_to})


def extend_login_context(context):
	"""Add Fayda actions without replacing the customized Frappe login template."""
	if context.get("_fayda_context_extended"):
		return
	if not is_fayda_configured():
		return
	context["_fayda_context_extended"] = True

	request = getattr(frappe.local, "request", None)
	request_args = getattr(request, "args", {})
	redirect_to = _safe_redirect(
		request_args.get("redirect-to"),
		default=frappe.conf.get("fayda_redirect_after_login", DEFAULT_REDIRECT_PATH),
	)
	direct_template = bool(context.get("_fayda_direct_template"))

	if cint(frappe.conf.get("fayda_enable_login", 1)):
		context["fayda_login_url"] = _flow_url(FLOW_LOGIN, redirect_to)
		if not direct_template:
			providers = context.get("provider_logins") or []
			if not any(provider.get("name") == "fayda" for provider in providers):
				providers.append(
					{
						"name": "fayda",
						"provider_name": _("Fayda digital ID"),
						"auth_url": context["fayda_login_url"],
						"icon": None,
					}
				)
			context["provider_logins"] = providers
			context["social_login"] = True

	if (
		not cint(context.get("disable_signup"))
		and cint(frappe.conf.get("fayda_enable_signup", 1))
	):
		signup_url = _flow_url(FLOW_SIGNUP, redirect_to)
		context["fayda_signup_url"] = signup_url
		if direct_template or not context.get("signup_form_template"):
			return

		signup_url = escape(signup_url, quote=True)
		signup_label = escape(_("Create account with Fayda"))
		signup_help = escape(_("Use your verified Fayda identity to create a learner account."))
		divider_label = escape(_("or create an account with email"))
		fayda_signup = f"""
		<div class="fayda-signup-option">
			<a href="{signup_url}"
				class="btn btn-block btn-default btn-sm btn-login-option btn-fayda"
				aria-label="{signup_label}">
				{signup_label}
			</a>
			<p class="fayda-signup-help text-muted">{signup_help}</p>
			<p class="text-muted login-divider">{divider_label}</p>
		</div>
		"""
		context["signup_form_template"] = fayda_signup + context["signup_form_template"]
