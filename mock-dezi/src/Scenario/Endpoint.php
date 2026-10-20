<?php

declare(strict_types=1);

namespace MockDezi\Scenario;

/**
 * The server-to-server endpoints whose availability the admin API selects.
 */
enum Endpoint: string
{
    case Discovery = 'discovery';
    case JwksIdToken = 'jwks_id_token';
    case JwksEnvelope = 'jwks_envelope';
    case JwksStatement = 'jwks_statement';
    case Token = 'token';
    case UserInfo = 'userinfo';
    case Status = 'status';

    /**
     * @return list<EndpointMode>
     */
    public function modes(): array
    {
        $common = [
            EndpointMode::Available,
            EndpointMode::ServerError,
            EndpointMode::Unavailable,
            EndpointMode::Timeout,
            EndpointMode::Redirect,
            EndpointMode::InvalidBody,
        ];

        return match ($this) {
            self::Discovery => [
                ...$common,
                EndpointMode::AuthMethodsNoneOnly,
                EndpointMode::WithoutAuthMethods,
                EndpointMode::WrongIssuer,
                EndpointMode::WrongJwksUri,
            ],
            self::JwksIdToken, self::JwksEnvelope, self::JwksStatement => [...$common, EndpointMode::EmptyKeySet],
            default => $common,
        };
    }

    public function allows(EndpointMode $mode): bool
    {
        return in_array($mode, $this->modes(), true);
    }
}
