<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc;

use DateTimeImmutable;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Configuration\OidcProviderConfiguration;
use JointIdentityProvider\Oidc\Configuration\TrustSettings;
use JointIdentityProvider\Oidc\Discovery\MetadataProvider;
use JointIdentityProvider\Oidc\Discovery\ProviderMetadata;
use JointIdentityProvider\Oidc\IdToken\IdTokenValidator;
use JointIdentityProvider\Oidc\Token\TokenClient;
use SensitiveParameter;

/**
 * The standard OIDC client (design §2): the authorisation request with PKCE, `state` and `nonce`, the
 * token exchange and the ID-token validation. All parameters come from the configuration.
 */
final readonly class OidcClient
{
    public function __construct(
        private MetadataProvider $metadata,
        private TokenClient $tokens,
        private IdTokenValidator $idTokens,
    ) {
    }

    /**
     * The authorisation request URL. Fails before the user is sent to the provider when the provider
     * does not list the configured client authentication method.
     *
     * @throws OidcFailure
     */
    public function authorizationUrl(
        OidcProviderConfiguration $provider,
        TrustSettings $trust,
        ClientConfiguration $client,
        #[SensitiveParameter] string $state,
        #[SensitiveParameter] string $nonce,
        #[SensitiveParameter] string $pkceVerifier,
    ): string {
        $metadata = $this->supportedMetadata($provider, $trust, $client);
        $authorization = $provider->authorization;

        $parameters = [
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => $client->redirectUri,
            'scope' => $authorization->scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => Pkce::challenge($pkceVerifier),
            'code_challenge_method' => Pkce::METHOD,
        ];
        if ($authorization->prompt !== null) {
            $parameters['prompt'] = $authorization->prompt;
        }
        if ($authorization->maxAge !== null) {
            $parameters['max_age'] = (string) $authorization->maxAge;
        }

        $endpoint = $metadata->authorizationEndpoint;

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?')
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Redeems the code and validates the ID token.
     *
     * @throws OidcFailure
     */
    public function completeLogin(
        OidcProviderConfiguration $provider,
        TrustSettings $trust,
        ClientConfiguration $client,
        #[SensitiveParameter] string $code,
        #[SensitiveParameter] string $pkceVerifier,
        #[SensitiveParameter] string $nonce,
        DateTimeImmutable $attemptStartedAt,
    ): AuthenticatedLogin {
        $metadata = $this->supportedMetadata($provider, $trust, $client);
        $tokens = $this->tokens->exchange($metadata, $client, $code, $pkceVerifier);
        $idToken = $this->idTokens->validate($tokens->idToken, $trust, $client, $nonce, $attemptStartedAt);

        return new AuthenticatedLogin($client, $metadata, $idToken, $tokens->accessToken, $attemptStartedAt);
    }

    private function supportedMetadata(
        OidcProviderConfiguration $provider,
        TrustSettings $trust,
        ClientConfiguration $client,
    ): ProviderMetadata {
        $metadata = $this->metadata->load($provider, $trust);
        if (!$metadata->supports($client->authentication)) {
            throw new OidcFailure(
                OidcFailureType::AuthenticationMethodNotSupported,
                'discovery does not list the configured authentication method',
            );
        }

        return $metadata;
    }
}
