<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc;

/**
 * Failure types of the standard OIDC steps (design §13, §14). Restartable types are the ones a new
 * attempt can fix: a cancel or an error reported by the provider, and a request that got no answer.
 */
enum OidcFailureType: string
{
    case ProviderCancelled = 'provider_cancelled';
    case ProviderError = 'provider_error';
    case CallbackInvalid = 'callback_invalid';
    case DiscoveryUnavailable = 'discovery_unavailable';
    case DiscoveryInvalid = 'discovery_invalid';
    case AuthenticationMethodNotSupported = 'authentication_method_not_supported';
    case TokenRequestUnavailable = 'token_request_unavailable';
    case ClientAuthenticationRefused = 'client_authentication_refused';
    case TokenRequestRefused = 'token_request_refused';
    case TokenResponseInvalid = 'token_response_invalid';
    case KeyFetchUnavailable = 'key_fetch_unavailable';
    case KeySetInvalid = 'key_set_invalid';
    case UnknownKey = 'unknown_key';
    case IdTokenInvalid = 'id_token_invalid';
    // A provider-signed message other than the ID token; the profile names it by its own type.
    case MessageInvalid = 'message_invalid';

    public function isRestartable(): bool
    {
        return in_array($this, [
            self::ProviderCancelled,
            self::ProviderError,
            self::DiscoveryUnavailable,
            self::TokenRequestUnavailable,
            self::KeyFetchUnavailable,
        ], true);
    }
}
