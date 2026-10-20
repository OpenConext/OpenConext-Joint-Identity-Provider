<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

/**
 * One client registration at the mock DEZI provider. Certificates are PEM strings.
 */
final readonly class ClientRegistration
{
    public const string AUTHENTICATION_PRIVATE_KEY_JWT = 'private_key_jwt';
    public const string AUTHENTICATION_NONE = 'none';

    /**
     * @param list<string> $redirectUris
     * @param list<string> $signingCertificates
     */
    public function __construct(
        public string $clientId,
        public array $redirectUris,
        public string $authentication,
        public array $signingCertificates,
        public string $encryptionCertificate,
        public string $encryptionKid,
        public string $envelopeAudience,
        public string $sectorIdentifier,
    ) {
    }

    public function allowsRedirectUri(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->redirectUris, true);
    }
}
