<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

/**
 * The mock DEZI provider's settings (config/mock-dezi.yaml). Values marked PROVISIONAL there are mock choices.
 */
final readonly class MockConfiguration
{
    public const string AUTHORIZE_PATH = '/authorize';
    public const string TOKEN_PATH = '/token';
    public const string USERINFO_PATH = '/userinfo';
    public const string STATUS_PATH_PREFIX = '/status/v1/verklaring/';

    /**
     * @param list<string> $tokenEndpointAuthMethods
     * @param array<string, ClientRegistration> $clients
     */
    public function __construct(
        public string $issuer,
        public array $tokenEndpointAuthMethods,
        public string $envelopeIssuer,
        public string $statementIssuer,
        public string $statementClaim,
        public string $loaAuthn,
        public string $loaDezi,
        public string $jsonSchema,
        public StatusResponseNames $statusNames,
        public int $authorizationRequestSeconds,
        public int $sessionSeconds,
        public int $codeSeconds,
        public int $accessTokenSeconds,
        public int $idTokenSeconds,
        public int $envelopeSeconds,
        public int $statementSeconds,
        public int $clockSkewSeconds,
        public int $maxClientAssertionLifetimeSeconds,
        public int $staleAuthTimeSeconds,
        public int $timeoutDelaySeconds,
        public string $pairwiseSalt,
        public array $clients,
    ) {
    }

    public function client(string $clientId): ?ClientRegistration
    {
        return $this->clients[$clientId] ?? null;
    }

    public function url(string $path): string
    {
        return $this->issuer . $path;
    }

    public function tokenEndpoint(): string
    {
        return $this->url(self::TOKEN_PATH);
    }

    public function statusUrl(string $verklaringId): string
    {
        return $this->url(self::STATUS_PATH_PREFIX . rawurlencode($verklaringId));
    }
}
