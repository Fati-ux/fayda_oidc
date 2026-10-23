(() => {
	"use strict";

	const BUTTON_ID = "fayda-login-button";
	const LOGIN_SECTION_SELECTOR = ".for-login";

	function getRedirectTarget() {
		const params = new URLSearchParams(window.location.search);
		const redirectTo = params.get("redirect-to") || params.get("redirect_to") || "/lms";

		if (!redirectTo.startsWith("/") || redirectTo.startsWith("//")) {
			return "/lms";
		}

		return redirectTo;
	}

	function buildLoginUrl() {
		const params = new URLSearchParams({
			flow: "login",
			redirect_to: getRedirectTarget(),
		});

		return `/fayda-login?${params.toString()}`;
	}

	function addFaydaButton() {
		if (document.getElementById(BUTTON_ID)) {
			return;
		}

		const section = document.querySelector(LOGIN_SECTION_SELECTOR);
		if (!section) {
			return;
		}

		const loginButton = section.querySelector(".btn-login");
		const actionArea = loginButton?.closest(".page-card-actions") || loginButton?.parentElement;
		if (!actionArea) {
			return;
		}

		const option = document.createElement("div");
		option.className = "fayda-login-option";
		option.innerHTML = `
			<div class="fayda-auth-separator" aria-hidden="true">
				<span>or</span>
			</div>
			<a id="${BUTTON_ID}" href="${buildLoginUrl()}"
				class="btn btn-block btn-default btn-sm btn-login-option btn-fayda">
				Sign in with Fayda
			</a>
		`;

		actionArea.insertAdjacentElement("afterend", option);
	}

	async function initializeFaydaLogin() {
		if (!document.querySelector(LOGIN_SECTION_SELECTOR)) {
			return;
		}

		try {
			const response = await fetch(
				"/api/method/fayda_oidc.api.is_fayda_configured",
				{
					credentials: "same-origin",
					headers: { Accept: "application/json" },
				}
			);
			if (!response.ok) {
				return;
			}

			const payload = await response.json();
			if (payload.message === true) {
				addFaydaButton();
			}
		} catch (error) {
			// Password login must continue to work if the optional Fayda check fails.
		}
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", initializeFaydaLogin, { once: true });
	} else {
		initializeFaydaLogin();
	}
})();
