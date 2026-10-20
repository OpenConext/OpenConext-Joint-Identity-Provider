<?php

declare(strict_types=1);

namespace MockDezi\Http;

use MockDezi\Configuration\ConfigurationLoader;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Key\KeyRing;
use MockDezi\Key\MessageType;
use MockDezi\Scenario\Endpoint;
use MockDezi\Scenario\EndpointMode;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Discovery and the key sets, one per message type at its own address (design §14).
 */
final readonly class MetadataController
{
    public function __construct(
        private ConfigurationLoader $loader,
        private KeyRing $keys,
        private EndpointGuard $guard,
    ) {
    }

    #[Route('/.well-known/openid-configuration', name: 'mock_dezi_discovery', methods: ['GET'])]
    public function discovery(Request $request): Response
    {
        $configuration = $this->loader->load();
        $mode = $this->guard->mode(Endpoint::Discovery);
        $failure = $this->guard->failure(
            $mode,
            $configuration->url('/.well-known/openid-configuration'),
            'application/json',
            $request,
        );
        if ($failure !== null) {
            return $failure;
        }

        // Shaped like DEZI acceptance discovery (design §14); values point at the mock.
        $metadata = [
            'issuer' => $mode === EndpointMode::WrongIssuer
                ? $configuration->issuer . '/wrong-issuer'
                : $configuration->issuer,
            'authorization_endpoint' => $configuration->url(MockConfiguration::AUTHORIZE_PATH),
            'token_endpoint' => $configuration->tokenEndpoint(),
            'userinfo_endpoint' => $configuration->url(MockConfiguration::USERINFO_PATH),
            'jwks_uri' => $configuration->url(
                ($mode === EndpointMode::WrongJwksUri ? MessageType::Statement : MessageType::IdToken)->jwksPath(),
            ),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code'],
            'scopes_supported' => ['openid'],
            'subject_types_supported' => ['pairwise'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => $mode === EndpointMode::AuthMethodsNoneOnly
                ? ['none']
                : $configuration->tokenEndpointAuthMethods,
            'claims_parameter_supported' => true,
        ];
        if ($mode === EndpointMode::WithoutAuthMethods) {
            unset($metadata['token_endpoint_auth_methods_supported']);
        }

        return Responses::json($metadata);
    }

    #[Route('/openid/connect/jwks.json', name: 'mock_dezi_jwks_id_token', methods: ['GET'])]
    public function idTokenKeys(Request $request): Response
    {
        return $this->keySet(MessageType::IdToken, $request);
    }

    #[Route('/envelope/jwks.json', name: 'mock_dezi_jwks_envelope', methods: ['GET'])]
    public function envelopeKeys(Request $request): Response
    {
        return $this->keySet(MessageType::Envelope, $request);
    }

    #[Route('/dezi/jwks.json', name: 'mock_dezi_jwks_statement', methods: ['GET'])]
    public function statementKeys(Request $request): Response
    {
        return $this->keySet(MessageType::Statement, $request);
    }

    private function keySet(MessageType $type, Request $request): Response
    {
        $configuration = $this->loader->load();
        $mode = $this->guard->mode($type->endpoint());
        $failure = $this->guard->failure(
            $mode,
            $configuration->url($type->redirectTarget()->jwksPath()),
            'application/json',
            $request,
        );
        if ($failure !== null) {
            return $failure;
        }

        return Responses::json(
            $mode === EndpointMode::EmptyKeySet ? ['keys' => []] : $this->keys->publicKeySet($type)->jsonSerialize(),
        );
    }
}
