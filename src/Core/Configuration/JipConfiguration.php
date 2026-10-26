<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Oidc\Configuration\KeyPair;

/**
 * The validated JIP configuration (design §17). Only ConfigurationLoader creates it, after every startup
 * check passed.
 */
final readonly class JipConfiguration
{
    /**
     * @param array<string, ServicePolicy> $services keyed by service entity ID
     */
    public function __construct(
        public Environment $environment,
        public EngineBlockConfiguration $engineBlock,
        public ProviderConfiguration $provider,
        public AttributeMapping $attributes,
        public BindingConfiguration $binding,
        public TransactionConfiguration $transactions,
        public array $services,
    ) {
    }

    /**
     * Every configured client key pair, for the certificate expiry alert (design §14).
     *
     * @return list<KeyPair>
     */
    public function clientKeyPairs(): array
    {
        $keyPairs = [];
        foreach ($this->provider->oidc->clients as $client) {
            array_push($keyPairs, ...$client->keyPairs());
        }

        return $keyPairs;
    }
}
