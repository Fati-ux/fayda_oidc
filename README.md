# SmartTutor Fayda OIDC

This Frappe app adds Fayda (VeriFayda 2.0/eSignet) authentication to the
SmartTutor ERPNext/LMS login page.

It adds two separate actions without replacing the customized SmartTutor login
template:

- **Login with Fayda** signs in an existing linked SmartTutor user. A verified
  Fayda email may be used to link an existing Website User.
- **Create account with Fayda** creates a Website User, assigns the
  `LMS Student` role when that role exists, links the Fayda OpenID subject, and
  signs the learner in.

Email/password login, forgot password, email signup, and other configured social
login providers continue to work.

## Security

The integration uses:

- OpenID Connect Authorization Code flow
- PKCE (`S256`)
- one-time state and nonce values stored in Frappe's Redis cache
- `private_key_jwt` client authentication
- ID token signature, issuer, audience, expiry, and nonce validation
- signed userinfo JWT validation when Fayda returns JWS userinfo
- safe local redirects only

Only Fayda's opaque `sub` value is stored on the User. Access tokens, ID tokens,
FIN, and other national identity numbers are not stored.

New Fayda users are Website Users. Existing System Users are never linked by
email automatically unless `fayda_allow_system_user_linking` is explicitly
enabled. The safer option for staff accounts is for an administrator to populate
the **Fayda Subject** field.

## Prerequisites

1. Frappe/ERPNext v15 and Frappe LMS installed on the SmartTutor site.
2. A Fayda relying-party application and approved credentials from the
   [Fayda Partner Portal](https://partner.fayda.et/).
3. The exact HTTPS callback URL registered with Fayda:

   ```text
   https://smarttutor.example.com/fayda-callback
   ```

4. The RSA private JWK corresponding to the public JWK registered with Fayda.
   Never commit this private key to Git.

## Installation

From the bench directory:

```bash
bench get-app <this-repository-url>
bench --site smarttutor.example.com install-app fayda_oidc
bench --site smarttutor.example.com migrate
bench build --app fayda_oidc
bench --site smarttutor.example.com clear-cache
```

For an app that is already installed, run the final three commands after pulling
this update. Migration imports the `custom_fayda_sub` User field.

## Configuration

Add the credentials to the site's private `site_config.json`:

```json
{
  "host_name": "https://smarttutor.com",
  "fayda_enabled": 1,
  "fayda_client_id": "CLIENT_ID_FROM_FAYDA",
  "fayda_redirect_uri": "https://smarttutor.com/fayda-callback",
  "fayda_private_key_type": "JWK_BASE64",
  "fayda_private_key_base64_jwk": "BASE64_ENCODED_PRIVATE_RSA_JWK",
  "fayda_discovery_url": "https://esignet.ida.fayda.et/.well-known/openid-configuration",
  "fayda_issuer": "https://esignet.ida.fayda.et",
  "fayda_authorization_endpoint": "https://esignet.ida.fayda.et/authorize",
  "fayda_token_endpoint": "https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token",
  "fayda_userinfo_endpoint": "https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo",
  "fayda_jwks_uri": "https://esignet.ida.fayda.et/.well-known/jwks.json",
  "fayda_scope": "openid profile email phone",
  "fayda_acr_values": "mosip:idp:acr:generated-code",
  "fayda_redirect_after_login": "/lms",
  "fayda_default_roles": ["LMS Student"]
}
```

The same safe template is available at
[`docs/fayda_site_config.example.json`](docs/fayda_site_config.example.json).
It intentionally contains no live credential.

The private JWK value can also be unencoded JWK JSON, but base64 is less
error-prone in a JSON configuration file. The JWK must include `kty`, `n`, `e`,
`d`, `p`, `q`, `dp`, `dq`, and `qi`. A `kid` should be included when Fayda
assigned one.

The endpoint values above match the eSignet environment supplied for SmartTutor.
When all five endpoint/validation settings are present, authentication does not
depend on discovery being available. If only the authorization endpoint is
configured, the app infers discovery from the same host rather than mixing Fayda
environments.

Optional settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `fayda_scope` | `openid profile email phone` | Consented OIDC scopes |
| `fayda_acr_values` | empty | Fayda authentication context |
| `fayda_claims` | empty | OIDC claims request, as JSON |
| `fayda_claims_locales` | empty | Preferred claim language |
| `fayda_userinfo_method` | `GET` | Set to `POST` if required by the environment |
| `fayda_enable_login` | `1` | Show the Fayda login action |
| `fayda_enable_signup` | `1` | Show the Fayda account-creation action |
| `fayda_email_domain` | `fayda.local` | Non-deliverable fallback domain when no verified email is returned |
| `fayda_trust_unverified_email` | `0` | Allow an unverified email claim to identify/link a user |
| `fayda_allow_system_user_linking` | `0` | Permit automatic staff account linking by verified email |
| `fayda_clock_skew_seconds` | `60` | JWT clock tolerance |

`fayda_trust_unverified_email` and `fayda_allow_system_user_linking` should stay
disabled in production unless the security implications are understood.

Plain HTTP is rejected. For local development only, it can be enabled with
`"fayda_allow_insecure_http": 1`.

Do not use `http://smarttutor.com/fayda-callback` in production. Set both
`host_name` and `fayda_redirect_uri` to HTTPS, and register that exact HTTPS
callback in the Fayda Partner Portal.

## SmartTutor login-page behavior

The app uses Frappe's login-page context extension hook, so it works with the
custom `apps/frappe/frappe/www/login.html` described in the SmartTutor
customization guide. The SmartTutor controller/template copies included with
this repository also call the extension directly and render dedicated Fayda
actions. A small website script also inserts **Sign in with Fayda** beside the
password-login actions when a customized theme does not render Frappe's generic
social-login container. It checks the server-side configuration first and does
not interfere with password login if that check fails.

The Fayda buttons appear only when `fayda_client_id` and
`fayda_private_key_base64_jwk` are configured. If Website Settings has
**Disable Signup** enabled, the Fayda account-creation action is also disabled.

The `/fayda-login` and `/fayda-callback` website routes include matching HTML
page artifacts as required by Frappe's website resolver. Their Python
controllers redirect to Fayda and complete the callback before either fallback
page is normally rendered.

## Administrator identity verification

The app includes a **Fayda Identity Verification** DocType for System Managers.
It provides a consent-based workflow for linking verified Fayda information to
an existing User:

1. Open a User and choose **Fayda → New Fayda Verification**.
2. Select the User, enter the resident's FAN or FIN, and save.
3. Choose **Verify with Fayda OTP**.
4. The browser opens Fayda's hosted authorization page. The resident—not the
   administrator—enters the OTP and approves sharing the requested claims.
5. SmartTutor validates the callback, signed tokens, issuer, audience, nonce,
   ACR, and userinfo signature.
6. The returned `individual_id` must match the encrypted FAN/FIN entered on the
   record. On success, the full identifier is cleared and only a masked value
   plus a keyed fingerprint are retained.
7. Verified name, phone, gender, birthdate, email reference, and Fayda subject
   are synchronized to the selected User. The User's login email is not renamed.

Fayda must enable the custom `individual_id` userinfo claim for the SmartTutor
relying-party client. Verification fails closed if the claim is unavailable or
does not match. This prevents an administrator from entering one FAN/FIN while
authenticating a different identity.

SmartTutor never receives or stores the OTP. It also never stores access tokens
or ID tokens in the DocType.

## Verification

1. Run the app tests:

   ```bash
   bench --site smarttutor.example.com run-tests --app fayda_oidc
   ```

2. Open `/login` in a private window.
3. Verify **Login with Fayda** is displayed.
4. Select **Sign up** and verify **Create account with Fayda** is displayed.
5. Create a learner with Fayda and confirm:
   - the browser returns to `/lms`;
   - the User is a Website User;
   - the User has `LMS Student`;
   - **Fayda Subject** is populated.
6. Log out and use **Login with Fayda** with the same Fayda identity.
7. Confirm a new, unlinked Fayda identity cannot create an account through the
   login-only action.
8. As a System Manager, create a **Fayda Identity Verification**, complete the
   hosted OTP flow, and verify the record and selected User are updated.

## Troubleshooting

- **Button not visible:** first run
  `bench --site smarttutor.example.com execute fayda_oidc.api.is_fayda_configured`.
  It must print a truthy value. If it does not, confirm the app is installed and
  both `fayda_client_id` and `fayda_private_key_base64_jwk` exist in that site's
  private configuration. Then run `bench migrate`, `bench build --app
  fayda_oidc`, clear the site cache, and restart the web workers.
- **Customized login still omits the button:** deploy both SmartTutor login
  files from `fayda_oidc/www/login.py` and `fayda_oidc/www/login.html`, or add
  the direct `extend_login_context(context)` call and dedicated Fayda blocks
  from those files to the customized Frappe login files.
- **Verification says `individual_id` is missing:** ask Fayda to enable the
  `individual_id` userinfo claim for this relying-party client. Do not disable
  identifier matching as a workaround.
- **Verification remains Pending OTP:** restart from the record. Pending
  transactions expire after ten minutes and cannot be reused.
- **Invalid redirect URI:** the configured callback must exactly match the URI
  registered with Fayda, including scheme and trailing slash behavior.
- **Signing key not found:** confirm the private JWK `kid` matches the registered
  public JWK and that the Fayda JWKS endpoint is reachable.
- **No account is linked:** use **Create account with Fayda** for a learner, or
  have an administrator link the Fayda subject to an existing account.
- **Synthetic email created:** Fayda did not return a verified email. This is
  expected; SmartTutor still links future logins using the opaque Fayda subject.

## License

MIT
