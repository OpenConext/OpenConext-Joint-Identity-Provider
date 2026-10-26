<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Token;

use JointIdentityProvider\Oidc\Configuration\ClientAuthentication;
use JointIdentityProvider\Oidc\Configuration\ClientConfiguration;
use JointIdentityProvider\Oidc\Discovery\ProviderMetadata;
use JointIdentityProvider\Oidc\Http\NoAnswer;
use JointIdentityProvider\Oidc\Http\ProviderHttpClient;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use SensitiveParameter;

/**
 * Redeems an authorisation code at the token endpoint (design §14). The authentication method comes
 * from the configuration only: it is never taken from discovery and never changed after a refusal.
 */
final readonly class TokenClient
{
    public function __construct(
        private ProviderHttpClient $http,
        private ClientAssertionFactory $assertions,
    ) {
    }

    /**
     * @throws OidcFailure
     */
    public function exchange(
        ProviderMetadata $metadata,
        ClientConfiguration $client,
        #[SensitiveParameter] string $code,
        #[SensitiveParameter] string $pkceVerifier,
    ): TokenResponse {
        if (!$metadata->supports($client->authentication)) {
            throw new OidcFailure(
                OidcFailureType::AuthenticationMethodNotSupported,
                'discovery does not list the configured authentication method',
            );
        }

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->redirectUri,
            'code_verifier' => $pkceVerifier,
            'client_id' => $client->clientId,
        ];
        if ($client->authentication === ClientAuthentication::PrivateKeyJwt) {
            $form['client_assertion_type'] = ClientAssertionFactory::ASSERTION_TYPE;
            $form['client_assertion'] = $this->assertions->create($client, $metadata->tokenEndpoint);
        }

        try {
            $response = $this->http->postForm($metadata->tokenEndpoint, $form);
        } catch (NoAnswer $exception) {
            throw new OidcFailure(OidcFailureType::TokenRequestUnavailable, 'no answer', $exception);
        }

        $body = $response->jsonObject();

        if ($response->statusCode >= 400) {
            if (($body['error'] ?? null) === 'invalid_client') {
                throw new OidcFailure(OidcFailureType::ClientAuthenticationRefused, 'invalid_client');
            }

            throw new OidcFailure(OidcFailureType::TokenRequestRefused, sprintf('HTTP %d', $response->statusCode));
        }

        if ($response->statusCode !== 200) {
            throw new OidcFailure(OidcFailureType::TokenResponseInvalid, 'answer is not HTTP 200');
        }
        if ($body === null) {
            throw new OidcFailure(OidcFailureType::TokenRequestUnavailable, 'invalid body');
        }

        $tokenType = $body['token_type'] ?? null;
        $idToken = $body['id_token'] ?? null;
        $accessToken = $body['access_token'] ?? null;
        // RFC 6749 §5.1: the token type value is case insensitive.
        if (!is_string($tokenType) || strcasecmp($tokenType, 'Bearer') !== 0) {
            throw new OidcFailure(OidcFailureType::TokenResponseInvalid, 'token_type is not Bearer');
        }
        if (!is_string($idToken) || $idToken === '') {
            throw new OidcFailure(OidcFailureType::TokenResponseInvalid, 'no id_token');
        }
        if (!is_string($accessToken) || $accessToken === '') {
            throw new OidcFailure(OidcFailureType::TokenResponseInvalid, 'no access_token');
        }

        return new TokenResponse($idToken, $accessToken);
    }
}
