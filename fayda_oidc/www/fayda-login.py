import frappe
from fayda_oidc.api import get_authorize_url

no_cache = 1


def get_context(context):
	redirect_location = get_authorize_url(
		flow=frappe.form_dict.get("flow", "login"),
		redirect_to=frappe.form_dict.get("redirect_to"),
	)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_location
	frappe.local.flags.redirect_location = redirect_location
	raise frappe.Redirect
