<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Support;

use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Oidc\Cache\ProviderCache;
use JointIdentityProvider\Oidc\Discovery\MetadataProvider;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\IdToken\IdTokenValidator;
use JointIdentityProvider\Oidc\Jose\SignedMessageVerifier;
use JointIdentityProvider\Oidc\Keys\KeyResolver;
use JointIdentityProvider\Oidc\OidcClient;
use JointIdentityProvider\Oidc\Token\ClientAssertionFactory;
use JointIdentityProvider\Oidc\Token\TokenClient;
use JointIdentityProvider\Tests\Support\ConfigurationFixture as Fixture;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;

/**
 * The OIDC client's services, wired by hand around a fake provider, a mock clock and a fresh cache.
 */
final class OidcFixture
{
    public readonly Fixture $configFixture;
    public readonly TestProvider $provider;
    public readonly MockClock $clock;
    public readonly ProviderHttpClient $http;
    public readonly ProviderCache $cache;

    public function __construct()
    {
        $this->configFixture = new Fixture();
        $this->provider = new TestProvider();
        $this->clock = new MockClock();
        $this->http = new ProviderHttpClient(new MockHttpClient($this->provider));
        $this->cache = new ProviderCache($this->configFixture->directory . '/provider-cache');
        Fixture::setEnv('EB_API_TOKEN', Fixture::API_TOKEN);
    }

    public function remove(): void
    {
        Fixture::setEnv('EB_API_TOKEN', null);
        $this->configFixture->remove();
    }

    /**
     * @param list<array{list<string|int>, mixed}> $changes
     */
    public function configuration(array $changes = []): JipConfiguration
    {
        $data = $this->configFixture->mockConfiguration();
        foreach ($changes as [$path, $value]) {
            /** @var array<string, mixed> $data */
            $data = Fixture::with($data, $path, $value);
        }

        return Fixture::loader($this->configFixture->writeConfiguration($data))->load();
    }

    public function keys(): KeyResolver
    {
        return new KeyResolver($this->http, $this->cache, $this->clock);
    }

    public function metadata(): MetadataProvider
    {
        return new MetadataProvider($this->http, $this->cache, $this->clock);
    }

    public function idTokens(): IdTokenValidator
    {
        return new IdTokenValidator(new SignedMessageVerifier($this->keys()), $this->clock);
    }

    public function tokens(): TokenClient
    {
        return new TokenClient($this->http, new ClientAssertionFactory($this->clock));
    }

    public function client(): OidcClient
    {
        return new OidcClient($this->metadata(), $this->tokens(), $this->idTokens());
    }
}
