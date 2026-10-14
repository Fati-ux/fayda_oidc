import frappe
from fayda_oidc.api import get_authorize_url


no_cache = True


def get_context(context):
    authorize_url = get_authorize_url()

    frappe.local.flags.redirect_location = authorize_url
    raise frappe.Redirect