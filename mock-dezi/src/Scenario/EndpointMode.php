<?php

declare(strict_types=1);

namespace MockDezi\Scenario;

/**
 * How one endpoint answers, for every request until the mode is changed or the state is reset.
 */
enum EndpointMode: string
{
    case Available = 'available';
    case ServerError = 'server_error';
    case Unavailable = 'unavailable';
    case Timeout = 'timeout';
    case Redirect = 'redirect';
    case InvalidBody = 'invalid_body';
    case AuthMethodsNoneOnly = 'auth_methods_none_only';
    case WithoutAuthMethods = 'without_auth_methods';
    case WrongIssuer = 'wrong_issuer';
    case WrongJwksUri = 'wrong_jwks_uri';
    case EmptyKeySet = 'empty_key_set';

    public function description(): string
    {
        return match ($this) {
            self::Available => 'normal answers',
            self::ServerError => '500',
            self::Unavailable => '503 with Retry-After',
            self::Timeout => 'the normal answer only after timeout_delay_seconds',
            self::Redirect => '302 (307 for POST); key sets redirect to another message type\'s approved key address',
            self::InvalidBody => '200 with a body that is not valid JSON or JOSE',
            self::AuthMethodsNoneOnly => 'discovery lists token endpoint authentication "none" only (as v0.7 p12)',
            self::WithoutAuthMethods => 'discovery omits token_endpoint_auth_methods_supported',
            self::WrongIssuer => 'discovery names another issuer',
            self::WrongJwksUri => 'discovery names the statement key address as jwks_uri',
            self::EmptyKeySet => 'the key set holds no keys',
        };
    }
}
