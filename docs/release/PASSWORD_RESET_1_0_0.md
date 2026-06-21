# Password Reset Release Contract 1.0.0

This document defines the supported password reset behavior for Raptor Balcony 1.0.0. It is a release companion to `RELEASE_FEATURE_MATRIX_1_0_0.md`, `API_ENDPOINT_MATRIX_1_0_0.md`, `ACCOUNT_FLOW_REGRESSION_TEST_PLAN_1_0_0.md`, and `docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md`. `PR_RESET_1_PASSWORD_RESET_LIFECYCLE_AUDIT.md` captures the original lifecycle audit. `PR_RESET_2_PASSWORD_RESET_2FA_OPTION_RESOLVER.md` defines the reset-context-aware 2FA option resolver. `PR_RESET_3_PASSWORD_RESET_SESSION_STATE_MACHINE.md` defines the pending reset session state model. `PR_RESET_4_PASSWORD_RESET_TOKEN_VERIFICATION_RESPONSE.md` adds `POST /account/password-reset/verify`. `PR_RESET_5_PASSWORD_RESET_2FA_SELECT_ENDPOINT.md` adds `POST /account/password-reset/twofactor/select`. `PR_RESET_6_PASSWORD_RESET_2FA_VERIFY_ENDPOINT.md` adds `POST /account/password-reset/twofactor/verify`. `PR_RESET_7_PASSWORD_RESET_FINALIZE_GATE.md` gates password promotion. `PR_RESET_8_PASSWORD_RESET_SQL_STATE_PERSISTENCE.md` persists reset 2FA sessions in PostgreSQL. `PR_RESET_9_PASSWORD_RESET_METHOD_REMOVAL_INTERACTION.md` revokes pending reset 2FA sessions when account 2FA methods change. `PR_RESET_10_PASSWORD_RESET_REGRESSION_COVERAGE.md` closes the reset series with regression coverage. `PR_HARDENING_2_PASSWORD_RESET_REQUEST_MODEL.md` normalizes the public request model around delivery channels only. `PR_HARDENING_3_PASSWORD_RESET_ABUSE_COUNTERS.md` splits reset-token verification, reset 2FA proof, and final password-promotion abuse counters.


Password reset artifacts expire after two minutes by default, matching the 1.0.0 short-lived reset and proof window contract.

## Supported delivery channels

`POST /account/password-reset/request` accepts exactly two delivery channels:

| Delivery channel | Destination prerequisite | Request proof issued | Reset 2FA decision point |
|---|---|---|---|
| `email` | Verified account email address | Backend-generated reset key code by email | After `POST /account/password-reset/verify` |
| `sms` | Verified SMS phone number | Backend-generated reset key code by SMS/text | After `POST /account/password-reset/verify` |

The request endpoint does not accept proof-strategy method names. A client chooses only where the reset bootstrap key code should be delivered. The backend then verifies the reset key code and computes reset-eligible 2FA options from the current account factors. Authenticator app proof is never requested during the initial reset request. It is selected and verified only through the reset 2FA session endpoints.

For email-bootstrapped reset, the reset 2FA resolver excludes `EMAIL` and `EMAIL_AND_AUTHENTICATOR_APP`, because email already supplied the bootstrap proof. Eligible reset 2FA options are therefore limited to `SMS`, `AUTHENTICATOR_APP`, and `SMS_AND_AUTHENTICATOR_APP` where those active verified methods exist. Verified-email-only accounts have no extra reset-eligible 2FA option after the email reset token is verified.

The password-reset SQL constraint stores canonical reset rows with `method = 'email'` or `method = 'sms'`, matching `delivery_channel = 'email'` or `delivery_channel = 'sms'`, `requires_key_code = true`, and `requires_totp = false`. TOTP is not a request-row requirement. It is represented by the SQL-backed pending reset 2FA session after token verification.

The client never sends `accountId`. The backend derives the owning account from the reset row loaded from PostgreSQL.

## Public API surface

### Request reset

`POST /account/password-reset/request`

Request body:

```json
{
  "identifier": "reader@example.com",
  "deliveryChannel": "email"
}
```

Successful-shaped requests return the same non-enumerating API envelope for known, unknown, ineligible, rate-limited, and delivery-failed accounts. The response includes a `resetId` for every valid-shaped request. For unknown or ineligible accounts, the `resetId` is a decoy that is not account-bound and cannot promote a password. If email/SMS delivery fails after a real reset artifact is created, the backend cancels that artifact internally before returning the same public response:

```json
{
  "success": true,
  "statusCode": 202,
  "code": "PASSWORD_RESET_REQUEST_ACCEPTED",
  "data": {
    "status": "accepted",
    "resetId": "018f7f7e-8da0-7d7c-a512-f5c7f72c2123",
    "message": "If the account can use this reset delivery channel, continue with the required reset proof."
  }
}
```

Malformed request bodies or unsupported delivery channels return `400 VALIDATION_FAILED` with the same envelope shape and validation errors:

```json
{
  "success": false,
  "statusCode": 400,
  "code": "VALIDATION_FAILED",
  "data": {
    "status": "accepted",
    "resetId": "00000000-0000-0000-0000-000000000000",
    "message": "If the account can use this reset delivery channel, continue with the required reset proof."
  },
  "errors": [
    {
      "field": "deliveryChannel",
      "messages": [
        "deliveryChannel must be email or sms."
      ]
    }
  ]
}
```

### Verify reset token

`POST /account/password-reset/verify`

This endpoint validates the reset key code without changing the password and without consuming the reset artifact.

Request body:

```json
{
  "resetId": "018f7f7e-8da0-7d7c-a512-f5c7f72c2123",
  "keyCode": "49382710"
}
```

When no reset-eligible 2FA path is required, the response uses `PASSWORD_RESET_TOKEN_VERIFIED`:

```json
{
  "success": true,
  "statusCode": 200,
  "code": "PASSWORD_RESET_TOKEN_VERIFIED",
  "data": {
    "status": "verified",
    "resetAccessToken": "<opaque-reset-access-token>",
    "requiresTwoFactor": false,
    "availableTwoFactorAuthConfigurations": [],
    "expiresAt": "<reset-expiration>"
  }
}
```

When the reset token is valid and reset 2FA must be selected next, the response uses `PASSWORD_RESET_TWO_FACTOR_SELECTION_REQUIRED` and advertises the reset-eligible configurations.

```json
{
  "success": true,
  "statusCode": 200,
  "code": "PASSWORD_RESET_TWO_FACTOR_SELECTION_REQUIRED",
  "data": {
    "status": "two_factor_selection_required",
    "resetAccessToken": "<opaque-reset-access-token>",
    "requiresTwoFactor": true,
    "availableTwoFactorAuthConfigurations": ["AUTHENTICATOR_APP"],
    "expiresAt": "<reset-expiration>"
  }
}
```

Wrong key-code verification records a failed reset attempt and returns the existing reset proof failure envelope. Successful verification does not promote the password.

### Select reset 2FA configuration

`POST /account/password-reset/twofactor/select`

This endpoint validates the reset access token, rejects unavailable reset 2FA configurations, selects the ordered proof path, and creates a pending reset 2FA session. The session is stored in PostgreSQL in `pending_password_reset_sessions`.

### Verify reset 2FA proof

`POST /account/password-reset/twofactor/verify`

The request carries the reset access token, the currently required method, and the submitted proof code:

```json
{
  "resetAccessToken": "<opaque-reset-access-token>",
  "method": "AUTHENTICATOR_APP",
  "code": "123456"
}
```

Successful completion returns `PASSWORD_RESET_TWO_FACTOR_COMPLETE` with `canChangePassword: true`. The endpoint does not change the password.

```json
{
  "success": true,
  "statusCode": 200,
  "code": "PASSWORD_RESET_TWO_FACTOR_COMPLETE",
  "data": {
    "status": "two_factor_complete",
    "resetAccessToken": "<opaque-reset-access-token>",
    "selectedConfiguration": "AUTHENTICATOR_APP",
    "currentRequiredMethod": null,
    "completedTwoFactorAuthMethods": ["AUTHENTICATOR_APP"],
    "remainingTwoFactorAuthMethods": [],
    "expiresAt": "<reset-expiration>",
    "canChangePassword": true
  }
}
```

Out-of-order proofs return `TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED`. Invalid authenticator proofs record a failed reset proof attempt and return a reset 2FA challenge failure.

### Finalize reset

`POST /account/password-reset/finalize`

When no reset-eligible 2FA path exists, finalize may use the reset id plus key-code proof:

```json
{
  "resetId": "018f7f7e-8da0-7d7c-a512-f5c7f72c2123",
  "keyCode": "49382710",
  "password": "new-password",
  "verifyPassword": "new-password"
}
```

When reset 2FA is required, finalize must use a reset access token whose pending reset session is complete:

```json
{
  "resetAccessToken": "<opaque-reset-access-token>",
  "password": "new-password",
  "verifyPassword": "new-password"
}
```

Successful finalize returns:

```json
{
  "success": true,
  "statusCode": 200,
  "code": "PASSWORD_RESET_COMPLETED",
  "data": {
    "status": "completed"
  }
}
```

Failure codes include:

```json
{ "code": "PASSWORD_RESET_INVALID_PROOF" }
{ "code": "PASSWORD_RESET_EXPIRED" }
{ "code": "PASSWORD_RESET_ATTEMPTS_EXCEEDED" }
{ "code": "PASSWORD_RESET_TWO_FACTOR_REQUIRED" }
{ "code": "PASSWORD_RESET_TWO_FACTOR_NOT_COMPLETE" }
```

## Security and storage invariants

- `PasswordResetSettings` controls expiration, attempt limits, delivery limits, and `CodeHashPepper`.
- `TotpSettings`, `SecretProtectionKey`, `ITotpSecretProtector`, and `IAuthenticatorAppEnrollmentRepo` define the shared authenticator-app proof boundary.
- The database keeps at most one active reset artifact per account by cancelling older active reset rows when a new real artifact is created.
- Raw key codes, raw TOTP codes, raw passwords, and `verifyPassword` are not stored.
- TOTP shared secrets are protected at rest and are loaded only through the shared authenticator enrollment contract.
- Password reset does not reset, replace, disable, or bypass MFA enrollment.
- Password promotion rotates `accounts.security_stamp`, invalidates old session trust, and leaves account-level cutoff remains unchanged.
- Pending reset 2FA sessions are revoked when SMS, email, or authenticator app availability changes.

## Regression coverage

Password reset coverage includes unit tests, `PasswordResetEndToEndRegressionTests`, `PasswordResetRepositorySqlIntegrationTests`, and the deferred SQL contract suite. Deferred SQL contract execution uses `TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS`, `TREEHAMMOCK_DB_CONTRACT_CONNECTION`, and `./eng/docker-sql-contracts.sh`; `TREEHAMMOCK_*` variables remain supported during the rename window, including `TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS` and `TREEHAMMOCK_DB_CONTRACT_CONNECTION`.

## CAPTCHA placeholder status

CAPTCHA remains a future release/build concern and is not implemented in the password reset flow for 1.0.0. Password reset does not currently implement a real CAPTCHA challenge. Password reset does not perform server-side challenge verification for CAPTCHA in 1.0.0. `CaptchaChallengeEnabled` must remain `false` for 1.0.0 because password reset CAPTCHA is a placeholder and not a production verification path. If CAPTCHA enforcement is accidentally enabled before the future challenge-verification PRs, request creation is intentionally suppressed rather than treated as security.
