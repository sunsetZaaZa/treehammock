# Raptor Balcony 1.0.0 API Endpoint Matrix

This matrix records the intended public API surface for 1.0.0. It is a release companion to `docs/release/RELEASE_FEATURE_MATRIX_1_0_0.md` and the SQL contract matrix.

## Endpoint status legend

| Status | Meaning |
|---|---|
| Complete | Endpoint is part of the 1.0.0 supported API. |
| Limited | Endpoint is supported only for the listed 1.0.0 boundary. |
| Public | Endpoint is callable without an active authenticated session and must be marked with the custom `AllowAnonymous` authorization intent at controller or action level. |
| Authenticated | Endpoint requires the custom `Authenticate` authorization model and must advertise `401` unless an action-level custom `AllowAnonymous` override applies. |


## Operational health endpoints

Health endpoints are release API surface for container, reverse-proxy, and deployment probes. They are public and intentionally return a small direct `HealthStatusResponse` payload instead of the standard `ApiResponse<T>` envelope so infrastructure probes can parse them without application-envelope coupling. Liveness is dependency-free. Readiness and dependency health check PostgreSQL and Dragonfly before declaring the API ready for traffic.

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| GET | `/health/live` | Public | none | `HealthStatusResponse` | No SQL required; process liveness only | Complete |
| GET | `/health/ready` | Public | none | `HealthStatusResponse` | PostgreSQL `select 1`; Dragonfly ping for active sessions, pending 2FA sessions, and abuse/idempotency counters | Complete; returns 503 when any required dependency is unhealthy |
| GET | `/health/dependencies` | Public | none | `HealthStatusResponse` | PostgreSQL `select 1`; Dragonfly ping for active sessions, pending 2FA sessions, and abuse/idempotency counters | Complete; detailed dependency report for operators |

## Account and authentication endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| POST | `/account/setupaccount` | Public | `AccountCreationRequest` | `AccountCreationResponse` | `setup_account_email`, `setup_account_both`, `start_verify_account` | Complete |
| POST | `/account/verifyaccount/resend` | Public | `AccountVerificationResendRequest` | `AccountVerificationResendResponse` | `resend_verify_account` | Complete |
| GET | `/account/verifyaccount` | Public | query verification token | HTML verification page | `verify_account_for_use`, `complete_verify_account`, `expire_verify_account` | Complete; ABUSE-9B applies Dragonfly public token/IP front brake before SQL token lookup |
| POST | `/account/requestaccess` | Public | `AuthenticateLogin` | `AuthenticateResponse` | Dragonfly login abuse counters, credential lookup functions, `set_session`, lockout functions, pending 2FA functions | Complete; 2FA accounts now return `AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED`, `twoFactorAccessToken`, and `availableTwoFactorAuthConfigurations`; SMS/email delivery waits for explicit selection |
| POST | `/account/reauthenticate` | Authenticated | `ReauthenticateRequest` | `ReauthenticateResponse` | `get_account_reauthentication_credentials`, `issue_sensitive_action_token` | Complete; issues short-lived sensitive-action token for authenticator setup or 2FA method removal |
| POST | `/account/logoff` | Authenticated | `AuthenticateLogoffRequest` or empty body | `AuthenticateLogoffResponse` | `logout_current_session` | Complete |
| POST | `/account/logoff/all` | Authenticated | `AuthenticateLogoffAllRequest` or empty body | `AuthenticateLogoffAllResponse` | `logout_all_sessions`, account security-stamp invalidation | Complete; requires `Idempotency-Key` |
| GET | `/account/sessions` | Authenticated | none | `AccountSessionsResponse` | `list_active_sessions` | Complete within single-session model |
| POST | `/account/sessions/revoke` | Authenticated | `AccountSessionRevokeRequest` | `AccountSessionRevokeResponse` | `revoke_session_for_account` | Complete within single-session model; requires `Idempotency-Key` |

## Account management endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| GET | `/account/view` | Authenticated | none | `AccountDetailsResponse` | `view_account` | Complete; profile now includes `twoFactorAuthConfiguration`, `twoFactorAuthMethods`, and `availableTwoFactorAuthConfigurations` for SMS, EMAIL, AUTHENTICATOR_APP, SMS+AUTHENTICATOR_APP, and EMAIL+AUTHENTICATOR_APP account states |
| POST | `/account/adjust` | Authenticated | `AccountEditRequest` | `AccountEditResponse` | `edit_account_username`, `request_account_email_change` | Complete; requires `Idempotency-Key` |
| GET | `/account/adjust/email/verify` | Public | query email-change token | `AccountEditResponse` | `complete_account_email_change` | Complete; ABUSE-9B applies Dragonfly public token/IP front brake before SQL token completion |
| POST | `/account/wipeout` | Authenticated | `AccountDeleteRequest` or empty body | `AccountDeleteResponse` | `request_account_delete` | Complete; requires `Idempotency-Key` |
| GET | `/account/wipeout/verify` | Public | query delete token | `AccountDeleteResponse` | `verify_account_delete_token` | Complete; ABUSE-9B applies Dragonfly public token/IP front brake before SQL token verification |
| POST | `/account/wipeout/finalize` | Authenticated | `AccountDeleteFinalizeRequest` | `AccountDeleteResponse` | `prepare_account_delete_finalize`, `commit_account_delete_finalize` | Complete; ABUSE-9B applies Dragonfly account/delete-token finalize front brake before SQL finalize; requires `Idempotency-Key` |

## Password reset endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| POST | `/account/password-reset/request` | Public | `RequestPasswordResetRequest` | `PasswordResetRequestResponse` | `lookup_password_reset_account`, rate-limit functions, `create_password_reset_request`, delivery provider | Creates the account-bound reset artifact or decoy reset id for a supported reset delivery channel with non-enumerating public response behavior |
| POST | `/account/password-reset/verify` | Public | `VerifyPasswordResetTokenRequest` | `VerifyPasswordResetTokenResponse` | `get_password_reset_request_for_finalize`, `register_password_reset_failed_attempt` | PR Reset-4 endpoint that validates the reset key-code, returns a reset access token, and advertises `PASSWORD_RESET_TOKEN_VERIFIED` or `PASSWORD_RESET_TWO_FACTOR_SELECTION_REQUIRED`; it does not consume the artifact or promote the password |
| POST | `/account/password-reset/twofactor/select` | Public | `SelectPasswordResetTwoFactorConfigurationRequest` | `SelectPasswordResetTwoFactorConfigurationResponse` | `get_password_reset_request_for_finalize`, `upsert_pending_password_reset_session`, delivery provider | Validates the reset access token, rejects unavailable reset 2FA configurations, selects the ordered reset proof path, persists the pending reset session in SQL, and issues SMS/email reset 2FA challenges when the selected reset path requires delivery |
| POST | `/account/password-reset/twofactor/verify` | Public pending reset-session context | `VerifyPasswordResetTwoFactorRequest` | `VerifyPasswordResetTwoFactorResponse` | `get_password_reset_request_for_finalize`, `get_pending_password_reset_session`, `upsert_pending_password_reset_session`, `get_verified_totp_enrollment_for_account`, `mark_totp_step_used` | Validates the reset access token, loads the SQL-backed pending reset 2FA session, rejects out-of-order proofs with `TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED`, verifies the current proof, and marks reset 2FA complete without changing the password |
| POST | `/account/password-reset/finalize` | Public | `FinalizePasswordResetRequest` | `FinalizePasswordResetResponse` | `get_password_reset_request_for_finalize`, `get_pending_password_reset_session`, `register_password_reset_failed_attempt`, `promote_password_reset`, `revoke_pending_password_reset_session` | Completes password reset after reset access-token gate or no-extra-2FA key-code proof; reset-eligible 2FA artifacts require completed SQL-backed `PasswordResetSession` before promotion |

Password reset request behavior is non-enumerating. Known accounts, unknown accounts, unavailable delivery destinations, rate-limited requests, and delivery failures return the generic accepted response with a `resetId` when the request shape is valid. Unknown and ineligible accounts receive a decoy `resetId` that is not account-bound and cannot promote a password; delivery failures cancel the real reset artifact before returning the same public response. The request body accepts only `deliveryChannel` values `email` and `sms`; authenticator proof is selected only after reset-token verification through reset 2FA session endpoints. Finalize derives `accountId` from `resetId`; the client never sends account identity for password promotion. Reset authenticator proof uses the same verified authenticator enrollment and shared replay marker as login 2FA, but must not create, replace, disable, reset, or bypass that enrollment. Full request, success, validation, invalid-proof, conflict, and rate-limit API examples are maintained in `docs/release/PASSWORD_RESET_1_0_0.md`.

## Two-factor endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| POST | `/account/setuptwofactormethod` | Authenticated | `SetupLayeredAuthenticateMethodRequest` | `SetupLayeredAuthenticateMethodResponse` | `begin_twofactor_setup`, `view_account`, delivery provider | Complete for `EMAIL` and `SMS_KEY`; requires `Idempotency-Key`; `EMAIL` setup is bound to `accounts.email_address` and rejects mismatched contact values |
| POST | `/account/verifytwofactormethod` | Authenticated | `VerifyLayeredAuthenticateMethodRequest` | `LayeredAuthenticateResponse` | `verify_twofactor_setup`, `set_twofactor_auth_detail` | Complete for `EMAIL` and `SMS_KEY`; ABUSE-9A applies Dragonfly setup-verification attempt front brake before SQL proof verification |
| POST | `/account/twofactor/authenticator/setup` | Authenticated | `StartAuthenticatorAppSetupRequest` | `StartAuthenticatorAppSetupResponse` | `validate_sensitive_action_token`, `view_account`, `begin_authenticator_app_setup` | Complete for local RFC 6238 authenticator provisioning; requires `Idempotency-Key` and `Sensitive-Action-Token`; TOTP-HARDEN-1 keeps idempotency replay secret-safe |
| POST | `/account/twofactor/authenticator/verify` | Authenticated | `VerifyAuthenticatorAppSetupRequest` | `VerifyAuthenticatorAppSetupResponse` | `get_pending_authenticator_app_setup`, `record_authenticator_app_setup_failure`, `complete_authenticator_app_setup_and_rotate_session` | Complete for local RFC 6238 setup proof; verifies TOTP locally, atomically rotates the current session into the new account security stamp, returns a fresh access token, and keeps idempotency replay secret-safe under TOTP-HARDEN-1 |
| POST | `/account/twofactor/authenticator/cancel` | Authenticated | `CancelAuthenticatorAppSetupRequest` | `CancelAuthenticatorAppSetupResponse` | `cancel_authenticator_app_setup` | Complete for pending authenticator setup cancellation; requires `Idempotency-Key`; TOTP-HARDEN-1 confirms verified enrollments are not deleted |
| POST | `/account/twofactor/method/remove` | Authenticated | `RemoveTwoFactorMethodRequest` | `RemoveTwoFactorMethodResponse` | `remove_twofactor_method`, sensitive-action validation | Complete for removing verified `EMAIL`, `SMS_KEY`, or `AUTHENTICATOR_APP`; requires `Idempotency-Key` and a `TWO_FACTOR_METHOD_REMOVE` sensitive-action token; removing authenticator app revokes/wipes only authenticator material while standalone SMS/email remain available when still verified; successful method removal also revokes pending password-reset 2FA sessions for the account |
| POST | `/account/twofactor/select` | Public pending-session context | `SelectTwoFactorConfigurationRequest` | `LayeredAuthenticateMethodsResponse` | pending 2FA Redis session, `record_twofactor_challenge_issued` | Complete for per-login selection of `SMS`, `EMAIL`, `AUTHENTICATOR_APP`, `SMS_AND_AUTHENTICATOR_APP`, and `EMAIL_AND_AUTHENTICATOR_APP`; SMS/email delivery happens only after this selection endpoint accepts the chosen configuration |
| POST | `/account/twofactorauth` | Public pending-session context | `LayeredAuthenticateRequest` | `LayeredAuthenticateResponse` | challenge record/failure functions, `get_verified_totp_enrollment_for_account`, `mark_totp_step_used`, promotion functions, `set_session`, `rotate_active_session` | Complete for ordered one-proof and two-proof verification; `SMS_AND_AUTHENTICATOR_APP` accepts SMS first then returns `AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED` until authenticator proof succeeds; `EMAIL_AND_AUTHENTICATOR_APP` follows the same email-first/authenticator-second state machine; out-of-order proofs return `TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED` |

Unsupported login two-factor methods for the current implemented 1.0.0 surface: OAuth/OIDC push and internal provider challenges. Authenticator-app setup is available for verified authenticated accounts, and TOTP-LOGIN-2 enables login method advertisement plus no-delivery challenge preparation for verified `AUTHENTICATOR_APP` enrollments. TOTP-LOGIN-1 documents the future shared-factor boundary in `docs/release/TOTP_LOGIN_1_AUTHENTICATOR_APP_BOUNDARY_PLAN.md`: Authy app, Google Authenticator, Microsoft Authenticator, and similar apps are supported through standard local RFC 6238/OATH TOTP provisioning; the same verified enrollment is intended to be usable for account login 2FA and password-reset TOTP proof; optional Twilio Verify TOTP support belongs behind a separate managed-provider lane. TOTP-LOGIN-3 completes submitted-code verification with `IAuthenticatorAppLoginVerifier`, shared TOTP replay marking, and final session promotion. PR 3 adds the ordered pending-session verification state machine: single-factor selections promote immediately after their proof, while SMS/email plus authenticator selections only promote after both strict proofs complete. PR 4 centralizes pending 2FA state transitions on `TwoFactorSession` so response remaining-method data and promotion checks are derived from the same model state. PR 5 mirrors the pending selection state into PostgreSQL: `begin_twofactor_auth_detail` creates a `SelectionRequired` row with available configurations and no challenge, while `record_twofactor_challenge_issued` persists selected configuration, required/completed method arrays, current expected method, and challenge counters. PR 7 adds `POST /account/twofactor/method/remove`; method removal expires pending 2FA sessions and recomputes future login choices from remaining verified factors.

## Account unlock endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| POST | `/account/unlock/start` | Public | `AccountRecoveryRequest` | `AccountRecoveryResponse` | `lookup_locked_recovery_account`, `start_unlock_account`, delivery provider | Complete for email and verified SMS delivery |
| POST | `/account/unlock/verify` | Public | `AccountRecoveryVerifyRequest` | `AccountRecoveryResponse` | `verify_unlock_account` | Complete; ABUSE-9A applies Dragonfly token-fingerprint and IP-fingerprint verify front brakes before SQL token verification |

Account unlock is enumeration-safe. Unknown accounts, unlocked accounts, missing delivery destinations, and delivery failures all use the public pending response shape. When an unlock artifact is stored, it records the selected delivery method internally.

## Activation endpoints

| Method | Route | Auth | Request model | Response model | Primary SQL/repository contract | Status |
|---|---|---|---|---|---|---|
| POST | `/activations/place` | Authenticated | `ActivationCreationRequest` | `ActivationCreationResponse` | `place_activation`, `cancel_activation_request` | Complete; requires `Idempotency-Key` |
| POST | `/activations/verify` | Authenticated | `ActivationDetailsRequest` | `ActivationDetailsResponse` | `verify_activation` | Complete; ABUSE-9C applies Dragonfly account/email/IP activation verify front brake before SQL code verification |
| POST | `/activations/disable` | Authenticated | `ActivationUnSubscribeRequest` | `ActivationUnSubscribeResponse` | `disable_activation` | Complete; requires `Idempotency-Key` |

Activation endpoints use explicit SQL `result/code` contracts. `ACCOUNT_SECURITY_STAMP_MISMATCH` maps to authentication failure instead of activation-not-found behavior. Activation creation rejects unsupported `term` and `recycle` values before state is stored, and SQL also returns explicit invalid-duration result codes as a defensive boundary.


## ABUSE-10 required authenticated mutation idempotency

Selected authenticated mutating endpoints require an `Idempotency-Key` header. The client must generate the key and send it on the first request and on any retry of that same logical operation. The API does not issue idempotency keys to the client. The API scopes the submitted key to account id, HTTP method, and route, stores only a fingerprinted key in Dragonfly, reserves the operation while the first request is running, and stores short-lived reservation/completion markers for 10 to 15 minutes. Duplicate requests with the same key do not repeat side effects. `POST /account/logoff` remains optional because logout should be naturally repeatable.

## 2FA TTL contract

`POST /account/requestaccess` creates pending pre-auth 2FA sessions with a two-minute TTL when verified account factors exist, but it does not send SMS/email keycodes until a later selection step. `POST /account/twofactor/select` stores the chosen per-login 2FA configuration on the pending session and caps the first issued proof challenge so keycodes cannot outlive that pending session. Password-reset artifacts created by `POST /account/password-reset/request` also expire after two minutes through `PasswordResetSettings:ExpirationMinutes`; expired reset artifacts cannot finalize.


Client request header example:

```http
Idempotency-Key: client-generated-key-12345
```

Client generation rules:

- Generate a unique key per logical mutation attempt.
- Reuse the same key only when retrying the exact same operation after a network/client uncertainty.
- Use 16 to 128 characters.
- Use only letters, digits, `_`, `-`, `.`, or `:`.
- Do not use email addresses, phone numbers, usernames, tokens, codes, passwords, or other secrets as the key.

Required endpoints:

- `POST /account/setuptwofactormethod`
- `POST /account/adjust`
- `POST /account/wipeout`
- `POST /account/wipeout/finalize`
- `POST /account/logoff/all`
- `POST /account/sessions/revoke`
- `POST /activations/place`
- `POST /activations/disable`

Optional endpoint:

- `POST /account/logoff`

The raw `Idempotency-Key` value is forbidden in logs, metrics, and cache keys.


Authenticator app no-delivery result: TWOFACTOR_WAITING_AUTHENTICATOR_APP.


## TOTP-ENROLL-6 endpoint note

`POST /account/twofactor/authenticator/setup` returns HTTP 409 with `TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED` when an account already has one active verified authenticator app. The endpoint does not replace authenticator apps automatically.


PR Reset-7 updates `/account/password-reset/finalize` to accept `resetAccessToken` and reject password promotion until reset 2FA is complete when required. PR Reset-8 persists pending reset 2FA sessions in PostgreSQL through `pending_password_reset_sessions` and SQL functions for get/upsert/revoke. PR Reset-9 revokes those pending reset 2FA sessions when authenticated 2FA method removal changes account factor availability.


## PR Reset-10 regression coverage

PR Reset-10 adds regression coverage that locks the public password-reset endpoint set, route templates, request payload types, and finalize gating contract without adding new endpoints.
