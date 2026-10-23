frappe.ui.form.on("User", {
	refresh(frm) {
		if (
			frm.is_new() ||
			!frappe.user_roles.includes("System Manager")
		) {
			return;
		}

		frm.add_custom_button(
			__("New Fayda Verification"),
			() => {
				frappe.route_options = { user: frm.doc.name };
				frappe.new_doc("Fayda Identity Verification");
			},
			__("Fayda")
		);
	},
});
