frappe.ui.form.on("Fayda Identity Verification", {
	refresh(frm) {
		if (frm.is_new()) {
			return;
		}

		if (frm.doc.status !== "Verified") {
			frm.add_custom_button(__("Verify with Fayda OTP"), () => {
				frappe.confirm(
					__(
						"The resident must be present to enter their OTP and approve profile sharing on Fayda's secure page. Continue?"
					),
					() => {
						frappe.call({
							method: "fayda_oidc.fayda_oidc.doctype.fayda_identity_verification.fayda_identity_verification.start_verification",
							args: { name: frm.doc.name },
							freeze: true,
							freeze_message: __("Preparing secure Fayda verification…"),
						}).then((response) => {
							if (response.message) {
								window.location.assign(response.message);
							}
						});
					}
				);
			}).addClass("btn-primary");
		}

		if (frm.doc.status === "Verified") {
			frm.add_custom_button(__("Sync Verified Data to User"), () => {
				frappe.call({
					method: "fayda_oidc.fayda_oidc.doctype.fayda_identity_verification.fayda_identity_verification.sync_to_user",
					args: { name: frm.doc.name },
					freeze: true,
					freeze_message: __("Synchronizing verified Fayda information…"),
				}).then(() => frm.reload_doc());
			});
		}
	},
});
