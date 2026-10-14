import frappe
from fayda_oidc.api import callback


no_cache = True


def get_context(context):
    callback(
        code=frappe.form_dict.get("code"),
        state=frappe.form_dict.get("state"),
    )