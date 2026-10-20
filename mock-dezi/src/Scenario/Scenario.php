<?php

declare(strict_types=1);

namespace MockDezi\Scenario;

/**
 * What one login does wrong, chosen on the login page or as the default through the admin API. The scenario
 * travels with the authorization code and the access token, so it affects only the login that selected it.
 * `success` changes nothing. Every other scenario changes one thing that JIP must refuse (design §14–§16, §18),
 * except the few marked "accepted", which JIP must accept.
 */
enum Scenario: string
{
    case Success = 'success';

    // Authorisation response (callback)
    case Cancel = 'cancel';
    case AuthorizeError = 'authorize_error';
    case CallbackWrongState = 'callback_wrong_state';
    case StaleAuthTime = 'stale_auth_time';
    case FutureAuthTime = 'future_auth_time';

    // Token response
    case TokenServerError = 'token_server_error';
    case TokenInvalidClient = 'token_invalid_client';
    case TokenInvalidGrant = 'token_invalid_grant';
    case TokenTypeNotBearer = 'token_type_not_bearer';
    case TokenWithoutIdToken = 'token_without_id_token';
    case TokenWithoutAccessToken = 'token_without_access_token';

    // ID token
    case IdTokenBadSignature = 'id_token_bad_signature';
    case IdTokenUnknownKid = 'id_token_unknown_kid';
    case IdTokenSignedWithStatementKey = 'id_token_signed_with_statement_key';
    case IdTokenAlgNone = 'id_token_alg_none';
    case IdTokenWrongIssuer = 'id_token_wrong_issuer';
    case IdTokenWrongAudience = 'id_token_wrong_audience';
    case IdTokenExtraAudience = 'id_token_extra_audience';
    case IdTokenWrongNonce = 'id_token_wrong_nonce';
    case IdTokenExpired = 'id_token_expired';
    case IdTokenWithoutAuthTime = 'id_token_without_auth_time';
    case IdTokenWithoutSub = 'id_token_without_sub';

    // UserInfo transport (JWE)
    case UserInfoServerError = 'userinfo_server_error';
    case UserInfoNotEncrypted = 'userinfo_not_encrypted';
    case UserInfoWrongKeyAlgorithm = 'userinfo_wrong_key_algorithm';
    case UserInfoWrongContentEncryption = 'userinfo_wrong_content_encryption';
    case UserInfoUnregisteredKey = 'userinfo_unregistered_key';
    case UserInfoUnknownKid = 'userinfo_unknown_kid';

    // Envelope
    case EnvelopeBadSignature = 'envelope_bad_signature';
    case EnvelopeUnknownKid = 'envelope_unknown_kid';
    case EnvelopeSignedWithIdTokenKey = 'envelope_signed_with_id_token_key';
    case EnvelopeJkuOtherAddress = 'envelope_jku_other_address';
    case EnvelopeWrongIssuer = 'envelope_wrong_issuer';
    case EnvelopeWrongAudience = 'envelope_wrong_audience';
    case EnvelopeExpired = 'envelope_expired';
    case EnvelopeWrongLoa = 'envelope_wrong_loa';
    case EnvelopeWithoutVerklaringId = 'envelope_without_verklaring_id';
    case EnvelopeWithSub = 'envelope_with_sub';
    case EnvelopeSubMismatch = 'envelope_sub_mismatch';

    // Statement
    case StatementBadSignature = 'statement_bad_signature';
    case StatementUnknownKid = 'statement_unknown_kid';
    case StatementSignedWithIdTokenKey = 'statement_signed_with_id_token_key';
    case StatementJkuOtherAddress = 'statement_jku_other_address';
    case StatementWrongIssuer = 'statement_wrong_issuer';
    case StatementExpired = 'statement_expired';
    case StatementNotYetValid = 'statement_not_yet_valid';
    case StatementTimeAsString = 'statement_time_as_string';
    case StatementVerklaringIdMismatch = 'statement_verklaring_id_mismatch';
    case StatementVerklaringIdNotUuid = 'statement_verklaring_id_not_uuid';
    case StatementWrongLoa = 'statement_wrong_loa';
    case StatementNumericDeziNummer = 'statement_numeric_dezi_nummer';
    case StatementEmptyAbonneeNummer = 'statement_empty_abonnee_nummer';
    case StatementDeziNummerNull = 'statement_dezi_nummer_null';
    case StatementRolCodeNull = 'statement_rol_code_null';
    case StatementVoorvoegselStringNull = 'statement_voorvoegsel_string_null';

    // Status check (each issues a fresh verklaring_id with this behaviour, so no other login is affected)
    case StatusRevoked = 'status_revoked';
    case StatusOtherStatus = 'status_other_status';
    case StatusNotFound = 'status_not_found';
    case StatusBadRequest = 'status_bad_request';
    case StatusServerError = 'status_server_error';
    case StatusTimeout = 'status_timeout';
    case StatusRedirect = 'status_redirect';
    case StatusInvalidBody = 'status_invalid_body';
    case StatusWrongId = 'status_wrong_id';

    public function step(): string
    {
        return match (true) {
            $this === self::Success => 'none',
            str_starts_with($this->value, 'token_') => 'token response',
            str_starts_with($this->value, 'id_token_') => 'ID token',
            str_starts_with($this->value, 'userinfo_') => 'UserInfo (JWE)',
            str_starts_with($this->value, 'envelope_') => 'envelope',
            str_starts_with($this->value, 'statement_') => 'statement',
            str_starts_with($this->value, 'status_') => 'status check',
            default => 'authorisation response',
        };
    }

    /**
     * The register behaviour of the fresh statement that a status scenario issues.
     */
    public function statementBehaviour(): ?StatementBehaviour
    {
        return match ($this) {
            self::StatusRevoked => StatementBehaviour::Revoked,
            self::StatusOtherStatus => StatementBehaviour::OtherStatus,
            self::StatusNotFound => StatementBehaviour::NotFound,
            self::StatusBadRequest => StatementBehaviour::BadRequest,
            self::StatusServerError => StatementBehaviour::ServerError,
            self::StatusTimeout => StatementBehaviour::Timeout,
            self::StatusRedirect => StatementBehaviour::Redirect,
            self::StatusInvalidBody => StatementBehaviour::InvalidBody,
            self::StatusWrongId => StatementBehaviour::WrongId,
            default => null,
        };
    }

    /**
     * True for the scenarios that JIP must accept.
     */
    public function isAccepted(): bool
    {
        return in_array($this, [self::Success, self::UserInfoUnknownKid, self::EnvelopeWithSub], true);
    }

    public function description(): string
    {
        return match ($this) {
            self::Success => 'Everything valid; the statement has the profile\'s register status',
            self::Cancel => 'The user cancels at DEZI: error=access_denied (PROVISIONAL error code)',
            self::AuthorizeError => 'DEZI reports an error: error=server_error',
            self::CallbackWrongState => 'The callback carries another state value',
            self::StaleAuthTime => 'auth_time lies stale_auth_time_seconds before the attempt (an earlier session)',
            self::FutureAuthTime => 'auth_time lies ten minutes in the future',
            self::TokenServerError => 'The token endpoint answers 500',
            self::TokenInvalidClient => 'The token endpoint answers 401 invalid_client after a valid request',
            self::TokenInvalidGrant => 'The token endpoint answers 400 invalid_grant after a valid request',
            self::TokenTypeNotBearer => 'token_type is "N_A" instead of Bearer',
            self::TokenWithoutIdToken => 'The token response has no id_token',
            self::TokenWithoutAccessToken => 'The token response has no access_token',
            self::IdTokenBadSignature => 'ID token signed with an unpublished key under the published kid',
            self::IdTokenUnknownKid => 'ID token signed with an unpublished key and kid',
            self::IdTokenSignedWithStatementKey => 'ID token signed with the statement key (another address)',
            self::IdTokenAlgNone => 'ID token with alg "none" and no signature',
            self::IdTokenWrongIssuer => 'ID token iss is another issuer',
            self::IdTokenWrongAudience => 'ID token aud is another client',
            self::IdTokenExtraAudience => 'ID token aud holds the client and an untrusted audience',
            self::IdTokenWrongNonce => 'ID token nonce differs from the request',
            self::IdTokenExpired => 'ID token exp lies in the past',
            self::IdTokenWithoutAuthTime => 'ID token has no auth_time',
            self::IdTokenWithoutSub => 'ID token has no sub',
            self::UserInfoServerError => 'UserInfo answers 500',
            self::UserInfoNotEncrypted => 'UserInfo returns the envelope JWS without encryption',
            self::UserInfoWrongKeyAlgorithm => 'JWE alg RSA-OAEP-256 instead of RSA-OAEP',
            self::UserInfoWrongContentEncryption => 'JWE enc A256GCM instead of A256CBC-HS512',
            self::UserInfoUnregisteredKey => 'JWE encrypted to a key the client never registered',
            self::UserInfoUnknownKid => 'Accepted: JWE kid matches no configured key; the registered key decrypts',
            self::EnvelopeBadSignature => 'Envelope signed with an unpublished key under the published kid',
            self::EnvelopeUnknownKid => 'Envelope signed with an unpublished key and kid',
            self::EnvelopeSignedWithIdTokenKey => 'Envelope signed with the ID-token key (another address)',
            self::EnvelopeJkuOtherAddress => 'Envelope signed with the ID-token key, jku pointing at its address',
            self::EnvelopeWrongIssuer => 'Envelope iss is another issuer',
            self::EnvelopeWrongAudience => 'Envelope aud is another audience',
            self::EnvelopeExpired => 'Envelope exp lies in the past',
            self::EnvelopeWrongLoa => 'Envelope loa_authn is substantial instead of high',
            self::EnvelopeWithoutVerklaringId => 'Envelope has no verklaring_id',
            self::EnvelopeWithSub => 'Accepted: envelope carries sub equal to the ID token\'s sub',
            self::EnvelopeSubMismatch => 'Envelope carries a sub that differs from the ID token\'s sub',
            self::StatementBadSignature => 'Statement sealed with an unpublished key under the published kid',
            self::StatementUnknownKid => 'Statement sealed with an unpublished key and kid',
            self::StatementSignedWithIdTokenKey => 'Statement sealed with the ID-token key; jku is the statement\'s',
            self::StatementJkuOtherAddress => 'Statement sealed with the ID-token key, jku pointing at its address',
            self::StatementWrongIssuer => 'Statement iss is another issuer',
            self::StatementExpired => 'Statement exp lies in the past',
            self::StatementNotYetValid => 'Statement nbf lies in the future',
            self::StatementTimeAsString => 'Statement exp is a string of digits instead of a number',
            self::StatementVerklaringIdMismatch => 'Statement verklaring_id differs from the envelope\'s',
            self::StatementVerklaringIdNotUuid => 'verklaring_id is not a UUID (equal in envelope and statement)',
            self::StatementWrongLoa => 'Statement loa_dezi is substantial instead of high',
            self::StatementNumericDeziNummer => 'Statement dezi_nummer is a JSON number',
            self::StatementEmptyAbonneeNummer => 'Statement abonnee_nummer is an empty string',
            self::StatementDeziNummerNull => 'Statement dezi_nummer is null',
            self::StatementRolCodeNull => 'Statement rol_code is null (an unconfirmed null shape)',
            self::StatementVoorvoegselStringNull => 'Statement voorvoegsel is the string "null"',
            self::StatusRevoked => 'Fresh statement whose status check answers the revoked status',
            self::StatusOtherStatus => 'Fresh statement whose status check answers another status',
            self::StatusNotFound => 'Fresh statement unknown to the status endpoint (404)',
            self::StatusBadRequest => 'Fresh statement whose status check answers 400',
            self::StatusServerError => 'Fresh statement whose status check answers 500',
            self::StatusTimeout => 'Fresh statement whose status check answers only after the timeout delay',
            self::StatusRedirect => 'Fresh statement whose status check answers with a redirect',
            self::StatusInvalidBody => 'Fresh statement whose status check answers a body that is not JSON',
            self::StatusWrongId => 'Fresh statement whose status check answers for another ID',
        };
    }
}
