<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

final readonly class ClientConfiguration
{
    // JIP's callback route; a client's redirect_uri must point at it.
    public const string CALLBACK_PATH = '/oidc/callback';

    /**
     * @param list<KeyPair> $decryptionKeys newest first; every entry decrypts
     */
    public function __construct(
        public string $name,
        public string $clientId,
        public string $redirectUri,
        public ClientAuthentication $authentication,
        public ?SigningKey $signingKey,
        public array $decryptionKeys,
    ) {
    }

    /**
     * @return list<KeyPair>
     */
    public function keyPairs(): array
    {
        return $this->signingKey === null
            ? $this->decryptionKeys
            : [$this->signingKey->keyPair, ...$this->decryptionKeys];
    }
}
