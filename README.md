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
3. The exact callback URL registered with Fayda:

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
  "fayda_enabled": 1,
  "fayda_client_id": "CLIENT_ID_FROM_FAYDA",
  "fayda_redirect_uri": "https://smarttutor.example.com/fayda-callback",
  "fayda_private_key_base64_jwk": "BASE64_ENCODED_PRIVATE_RSA_JWK",
  "fayda_discovery_url": "https://auth.fayda.et/.well-known/openid-configuration",
  "fayda_redirect_after_login": "/lms",
  "fayda_default_roles": ["LMS Student"]
}
```

The private JWK value can also be unencoded JWK JSON, but base64 is less
error-prone in a JSON configuration file. The JWK must include `kty`, `n`, `e`,
`d`, `p`, `q`, `dp`, `dq`, and `qi`. A `kid` should be included when Fayda
assigned one.

If Fayda provides environment-specific URLs instead of discovery, these settings
override the discovered values:

```json
{
  "fayda_issuer": "ISSUER_FROM_FAYDA",
  "fayda_authorization_endpoint": "AUTHORIZATION_URL_FROM_FAYDA",
  "fayda_token_endpoint": "TOKEN_URL_FROM_FAYDA",
  "fayda_userinfo_endpoint": "USERINFO_URL_FROM_FAYDA",
  "fayda_jwks_uri": "JWKS_URL_FROM_FAYDA"
}
```

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

## SmartTutor login-page behavior

The app uses Frappe's login-page context extension hook, so it works with the
custom `apps/frappe/frappe/www/login.html` described in the SmartTutor
customization guide. No further edits to Frappe or LMS core files are required.

The Fayda buttons appear only when `fayda_client_id` and
`fayda_private_key_base64_jwk` are configured. If Website Settings has
**Disable Signup** enabled, the Fayda account-creation action is also disabled.

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

## Troubleshooting

- **Button not visible:** confirm the app is installed, the two required local
  credentials are set, then run `bench build --app fayda_oidc` and clear cache.
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
