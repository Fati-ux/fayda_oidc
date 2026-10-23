import base64
import hashlib
import json
import time
import uuid
from urllib.parse import urlencode

import frappe
import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.auth import LoginManager
from frappe.utils.data import add_to_date, now_datetime


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_to_int(value):
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def get_settings():
    return {
        "client_id": frappe.conf.fayda_client_id,
        "redirect_uri": frappe.conf.fayda_redirect_uri,
        "authorization_endpoint": frappe.conf.fayda_authorization_endpoint,
        "token_endpoint": frappe.conf.fayda_token_endpoint,
        "userinfo_endpoint": frappe.conf.fayda_userinfo_endpoint,
        "scope": frappe.conf.get("fayda_scope", "openid profile email phone"),
        "acr_values": frappe.conf.get("fayda_acr_values"),
        "base64_jwk": frappe.conf.fayda_private_key_base64_jwk,
    }


def load_private_key_from_base64_jwk():
    jwk_json = base64.b64decode(frappe.conf.fayda_private_key_base64_jwk).decode()
    jwk = json.loads(jwk_json)

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

    return private_numbers.private_key(), jwk.get("kid")


def create_client_assertion():
    s = get_settings()

    private_key, _kid = load_private_key_from_base64_jwk()

    now = int(time.time())

    payload = {
        "iss": s["client_id"],
        "sub": s["client_id"],
        "aud": s["token_endpoint"],
        "iat": now,
        "exp": now + 900,
    }

    headers = {
        "alg": "RS256",
        "typ": "JWT",
    }

    assertion = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers,
    )

    return assertion



@frappe.whitelist(allow_guest=True)
def get_authorize_url():
    s = get_settings()

    state = frappe.generate_hash(length=32)
    nonce = frappe.generate_hash(length=32)

    verifier = b64url(
        uuid.uuid4().bytes
        + uuid.uuid4().bytes
    )

    challenge = b64url(
        hashlib.sha256(
            verifier.encode("utf-8")
        ).digest()
    )

    # Persist the OIDC transaction in MariaDB.
    create_oidc_transaction(
        state=state,
        nonce=nonce,
        code_verifier=verifier,
    )

    params = {
        "response_type": "code",
        "client_id": s["client_id"],
        "redirect_uri": s["redirect_uri"],
        "scope": s["scope"],
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    if s.get("acr_values"):
        params["acr_values"] = s["acr_values"]

    return (
        s["authorization_endpoint"]
        + "?"
        + urlencode(params)
    )

@frappe.whitelist(allow_guest=True)
def callback(
    code=None,
    state=None,
    nonce=None,
    error=None,
    error_description=None,
):
    """
    Fayda / eSignet OIDC callback.

    Flow:
        Fayda
            -> /fayda-callback
            -> /api/method/fayda_oidc.api.callback
            -> validate state / nonce
            -> recover PKCE verifier from DB
            -> exchange authorization code for token
            -> call userinfo
            -> create / find ERPNext user
            -> login ERPNext user
            -> redirect to /app
    """

    log_name = None
    transaction = None

    # ---------------------------------------------------------
    # Create callback log immediately
    # ---------------------------------------------------------

    try:
        log_name = create_callback_log(
            state=state,
            code=code,
            error=error,
            error_description=error_description,
        )
    except Exception:
        frappe.log_error(
            frappe.get_traceback(),
            "Fayda OIDC Callback Log Creation Failed",
        )

    try:
        # -----------------------------------------------------
        # 1. Handle error returned directly by Fayda
        # -----------------------------------------------------

        if error:
            message = error_description or error

            update_callback_log(
                log_name,
                status="Failed",
                error=error,
                error_description=message,
            )

            frappe.throw(
                f"Fayda authentication failed: {message}"
            )

        # -----------------------------------------------------
        # 2. Validate callback parameters
        # -----------------------------------------------------

        if not code:
            update_callback_log(
                log_name,
                status="Failed",
                error="missing_code",
                error_description=(
                    "Fayda callback did not contain an "
                    "authorization code."
                ),
            )

            frappe.throw(
                "Missing Fayda authorization code."
            )

        if not state:
            update_callback_log(
                log_name,
                status="Failed",
                error="missing_state",
                error_description=(
                    "Fayda callback did not contain state."
                ),
            )

            frappe.throw(
                "Missing Fayda OAuth state."
            )

        # -----------------------------------------------------
        # 3. Recover OAuth / PKCE transaction from MariaDB
        # -----------------------------------------------------

        transaction = get_oidc_transaction(state)

        if not transaction:
            update_callback_log(
                log_name,
                status="Failed",
                error="state_not_found",
                error_description=(
                    "OIDC transaction was not found, "
                    "has expired, or was already used."
                ),
            )

            frappe.throw(
                "Fayda login transaction was not found "
                "or has expired. Please start login again."
            )

        expected_state = transaction.state
        expected_nonce = transaction.nonce

        # Password field must be decrypted with get_password().
        code_verifier = transaction.get_password(
            "code_verifier"
        )

        # -----------------------------------------------------
        # 4. Validate state
        # -----------------------------------------------------

        if state != expected_state:
            update_callback_log(
                log_name,
                status="Failed",
                error="invalid_state",
                error_description=(
                    "Returned OAuth state does not match "
                    "the stored transaction state."
                ),
            )

            frappe.throw(
                "Invalid Fayda OAuth state."
            )

        # -----------------------------------------------------
        # 5. Validate nonce
        #
        # Fayda currently sends nonce as a callback query
        # parameter. Validate it when supplied.
        # -----------------------------------------------------

        if nonce and expected_nonce:
            if nonce != expected_nonce:
                update_callback_log(
                    log_name,
                    status="Failed",
                    error="invalid_nonce",
                    error_description=(
                        "Returned Fayda nonce does not "
                        "match the stored nonce."
                    ),
                )

                frappe.throw(
                    "Invalid Fayda nonce."
                )

        # -----------------------------------------------------
        # 6. Validate PKCE verifier
        # -----------------------------------------------------

        if not code_verifier:
            update_callback_log(
                log_name,
                status="Failed",
                error="missing_code_verifier",
                error_description=(
                    "The PKCE code verifier could not "
                    "be recovered from the transaction."
                ),
            )

            frappe.throw(
                "Missing Fayda PKCE code verifier."
            )

        # -----------------------------------------------------
        # 7. Load Fayda settings
        # -----------------------------------------------------

        s = get_settings()

        # -----------------------------------------------------
        # 8. Generate private_key_jwt client assertion
        # -----------------------------------------------------

        client_assertion = create_client_assertion()

        if not client_assertion:
            update_callback_log(
                log_name,
                status="Failed",
                error="client_assertion_failed",
                error_description=(
                    "Unable to generate Fayda "
                    "client assertion."
                ),
            )

            frappe.throw(
                "Unable to generate Fayda client assertion."
            )

        # -----------------------------------------------------
        # 9. Exchange authorization code for tokens
        # -----------------------------------------------------

        token_request = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": s["redirect_uri"],
    "client_id": s["client_id"],
    "client_assertion_type": (
        "urn:ietf:params:oauth:"
        "client-assertion-type:jwt-bearer"
    ),
    "client_assertion": client_assertion,
    "code_verifier": code_verifier,
}

        try:
            token_res = requests.post(
    s["token_endpoint"],
    data=token_request,
    headers={
        "Content-Type": "application/x-www-form-urlencoded"
    },
    timeout=30,
)

        except requests.RequestException as exc:
            update_callback_log(
                log_name,
                status="Failed",
                error="token_connection_error",
                error_description=str(exc),
            )

            frappe.throw(
                f"Unable to connect to Fayda token "
                f"endpoint: {exc}"
            )

        # -----------------------------------------------------
        # 10. Handle token endpoint errors
        # -----------------------------------------------------

        if not token_res.ok:
            response_text = token_res.text or ""

            update_callback_log(
        log_name,
        status="Failed",
        error=f"token_http_{token_res.status_code}",
        error_description=response_text[:4000],
          )

        frappe.log_error(
        title="Fayda Token Exchange Failed",
        message=(
            f"HTTP Status: {token_res.status_code}\n\n"
            f"Token Endpoint: {s['token_endpoint']}\n\n"
            f"Client ID: {s['client_id']}\n\n"
            f"Redirect URI: {s['redirect_uri']}\n\n"
            f"Code Verifier Length: {len(code_verifier)}\n\n"
            f"Response:\n{response_text}"
        ),
    )

        frappe.throw(
        f"Fayda token request failed with HTTP "
        f"{token_res.status_code}: "
        f"{response_text[:1000]}"
    )

        # -----------------------------------------------------
        # 11. Decode token response
        # -----------------------------------------------------

        try:
            token_data = token_res.json()

        except ValueError:
            update_callback_log(
                log_name,
                status="Failed",
                error="invalid_token_json",
                error_description=(
                    token_res.text[:4000]
                ),
            )

            frappe.throw(
                "Fayda token endpoint returned "
                "invalid JSON."
            )

        access_token = token_data.get(
            "access_token"
        )

        id_token = token_data.get(
            "id_token"
        )

        if not access_token:
            # Do not save the actual token response if it may
            # contain sensitive token values.
            safe_keys = list(token_data.keys())

            update_callback_log(
                log_name,
                status="Failed",
                error="missing_access_token",
                error_description=(
                    "Fayda token endpoint returned "
                    "success but access_token was missing. "
                    f"Response keys: {safe_keys}"
                ),
            )

            frappe.throw(
                "Fayda did not return an access token."
            )

        update_callback_log(
            log_name,
            status="Token Received",
        )

        # -----------------------------------------------------
        # 12. Call OIDC UserInfo endpoint
        # -----------------------------------------------------

        try:
            userinfo_res = requests.get(
                s["userinfo_endpoint"],
                headers={
                    "Authorization":
                        f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                timeout=30,
            )

        except requests.RequestException as exc:
            update_callback_log(
                log_name,
                status="Failed",
                error="userinfo_connection_error",
                error_description=str(exc),
            )

            frappe.throw(
                f"Unable to connect to Fayda "
                f"userinfo endpoint: {exc}"
            )

        # -----------------------------------------------------
        # 13. Handle UserInfo HTTP errors
        # -----------------------------------------------------

        if not userinfo_res.ok:
            response_text = (
                userinfo_res.text or ""
            )

            update_callback_log(
                log_name,
                status="Failed",
                error=(
                    f"userinfo_http_"
                    f"{userinfo_res.status_code}"
                ),
                error_description=(
                    response_text[:4000]
                ),
            )

            frappe.log_error(
                message=(
                    f"HTTP Status: "
                    f"{userinfo_res.status_code}\n\n"
                    f"Response:\n{response_text}"
                ),
                title="Fayda UserInfo Failed",
            )

            frappe.throw(
                f"Fayda userinfo request failed "
                f"with HTTP "
                f"{userinfo_res.status_code}."
            )

        # -----------------------------------------------------
        # 14. Decode UserInfo
        # -----------------------------------------------------

        try:
            profile = userinfo_res.json()

        except ValueError:
            update_callback_log(
                log_name,
                status="Failed",
                error="invalid_userinfo_json",
                error_description=(
                    userinfo_res.text[:4000]
                ),
            )

            frappe.throw(
                "Fayda userinfo endpoint returned "
                "invalid JSON."
            )

        # -----------------------------------------------------
        # 15. Validate required subject identifier
        # -----------------------------------------------------

        fayda_sub = profile.get("sub")

        if not fayda_sub:
            update_callback_log(
                log_name,
                status="Failed",
                error="missing_sub",
                error_description=(
                    "Fayda userinfo response did not "
                    "contain the OIDC sub claim."
                ),
                userinfo_json=json.dumps(
                    profile,
                    ensure_ascii=False,
                    indent=2,
                ),
            )

            frappe.throw(
                "Fayda user information does not "
                "contain a subject identifier."
            )

        email = profile.get("email")

        phone = (
            profile.get("phone_number")
            or profile.get("phone")
        )

        # -----------------------------------------------------
        # 16. Save safe UserInfo data to callback log
        # -----------------------------------------------------

        update_callback_log(
            log_name,
            status="User Info Received",
            fayda_sub=fayda_sub,
            email=email,
            phone=phone,
            userinfo_json=json.dumps(
                profile,
                ensure_ascii=False,
                indent=2,
            ),
        )

        # -----------------------------------------------------
        # 17. Mark transaction used BEFORE logging user in
        #
        # Prevent authorization code replay.
        # -----------------------------------------------------

        transaction.db_set(
            "used",
            1,
            update_modified=False,
        )

        frappe.db.commit()

        # -----------------------------------------------------
        # 18. Find / create ERPNext User
        # -----------------------------------------------------

        user = login_or_create_user(
            profile,
            redirect=False,
        )

        if not user:
            update_callback_log(
                log_name,
                status="Failed",
                error="erpnext_user_failed",
                error_description=(
                    "Unable to resolve or create "
                    "ERPNext user."
                ),
            )

            frappe.throw(
                "Unable to create or find "
                "ERPNext user."
            )

        # -----------------------------------------------------
        # 19. Update successful callback log
        # -----------------------------------------------------

        update_callback_log(
            log_name,
            status="Success",
            erpnext_user=user,
        )

        # -----------------------------------------------------
        # 20. Delete completed transaction
        # -----------------------------------------------------

        try:
            frappe.delete_doc(
                "Fayda OIDC Transaction",
                transaction.name,
                ignore_permissions=True,
                force=True,
            )

            frappe.db.commit()

        except Exception:
            # Successful login should not fail merely because
            # cleanup failed.
            frappe.log_error(
                frappe.get_traceback(),
                "Fayda OIDC Transaction Cleanup Failed",
            )

        # -----------------------------------------------------
        # 21. Redirect authenticated user to ERPNext
        # -----------------------------------------------------

        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = "/app"

        return

    except frappe.ValidationError:
        # frappe.throw() already creates a useful error.
        raise

    except Exception as exc:
        # -----------------------------------------------------
        # Unexpected error
        # -----------------------------------------------------

        try:
            update_callback_log(
                log_name,
                status="Failed",
                error=exc.__class__.__name__,
                error_description=str(exc),
            )
        except Exception:
            pass

        frappe.log_error(
            frappe.get_traceback(),
            "Fayda OIDC Callback Failed",
        )

        raise


def login_or_create_user(profile, redirect=True):
    fayda_sub = profile.get("sub")

    if not fayda_sub:
        frappe.throw(
            "Fayda userinfo does not contain sub."
        )

    email = profile.get("email")

    phone = (
        profile.get("phone_number")
        or profile.get("phone")
    )

    first_name = (
        profile.get("given_name")
        or profile.get("name")
        or "Fayda"
    )

    last_name = (
        profile.get("family_name")
        or ""
    )

    # First identify by Fayda subject.
    user = frappe.db.get_value(
        "User",
        {
            "custom_fayda_sub": fayda_sub
        },
        "name",
    )

    # Fall back to verified email.
    if not user and email:
        user = frappe.db.get_value(
            "User",
            {"email": email},
            "name",
        )

    # Fayda may not always supply email.
    if not email:
        email = f"{fayda_sub}@fayda.local"

    if not user:
        doc = frappe.get_doc({
            "doctype": "User",
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "enabled": 1,
            "send_welcome_email": 0,
            "user_type": "System User",
            "mobile_no": phone,
            "custom_fayda_sub": fayda_sub,
        })

        doc.insert(
            ignore_permissions=True
        )

        user = doc.name

    else:
        frappe.db.set_value(
            "User",
            user,
            "custom_fayda_sub",
            fayda_sub,
            update_modified=False,
        )

        if phone:
            frappe.db.set_value(
                "User",
                user,
                "mobile_no",
                phone,
                update_modified=False,
            )

    frappe.db.commit()

    # Frappe v15
    frappe.local.login_manager = LoginManager()
    frappe.local.login_manager.login_as(user)

    if redirect:
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = "/app"

    return user


def create_callback_log(
    state=None,
    code=None,
    error=None,
    error_description=None,
):
    try:
        log = frappe.get_doc({
            "doctype": "Fayda OIDC Log",
            "status": "Received",
            "callback_time": now_datetime(),
            "state": state,
            "code_received": 1 if code else 0,
            "error": error,
            "error_description": error_description,
        })

        log.insert(ignore_permissions=True)
        frappe.db.commit()

        return log.name

    except Exception:
        frappe.log_error(
            frappe.get_traceback(),
            "Fayda Callback Log Creation Failed"
        )

        return None


def update_callback_log(log_name, **values):
    if not log_name:
        return

    try:
        frappe.db.set_value(
            "Fayda OIDC Log",
            log_name,
            values,
            update_modified=True,
        )

        frappe.db.commit()

    except Exception:
        frappe.log_error(
            frappe.get_traceback(),
            "Fayda Callback Log Update Failed"
        )    


def create_oidc_transaction(state, nonce, code_verifier):
    # Remove expired transactions.
    frappe.db.delete(
        "Fayda OIDC Transaction",
        {
            "expires_at": ["<", now_datetime()]
        }
    )

    doc = frappe.get_doc({
        "doctype": "Fayda OIDC Transaction",
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "expires_at": add_to_date(
            now_datetime(),
            minutes=10
        ),
        "used": 0,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return doc.name


def get_oidc_transaction(state):
    if not state:
        return None

    if not frappe.db.exists(
        "Fayda OIDC Transaction",
        state
    ):
        return None

    doc = frappe.get_doc(
        "Fayda OIDC Transaction",
        state
    )

    if doc.used:
        return None

    if doc.expires_at and doc.expires_at < now_datetime():
        frappe.delete_doc(
            "Fayda OIDC Transaction",
            doc.name,
            ignore_permissions=True
        )
        frappe.db.commit()

        return None

    return doc
