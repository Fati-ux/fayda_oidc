import frappe
from fayda_oidc.api import callback

no_cache = 1


def get_context(context):
	callback(
		code=frappe.form_dict.get("code"),
		state=frappe.form_dict.get("state"),
		error=frappe.form_dict.get("error"),
		error_description=frappe.form_dict.get("error_description"),
	)
