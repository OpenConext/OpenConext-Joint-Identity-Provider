<?php

declare(strict_types=1);

namespace MockDezi\Configuration;

use Jose\Component\KeyManagement\JWKFactory;
use Throwable;

/**
 * Reads config/mock-dezi.yaml and the client certificates it names. Refuses unknown or mistyped settings.
 */
final class ConfigurationLoader
{
    private ?MockConfiguration $configuration = null;

    public function __construct(
        private readonly string $projectDir,
        private readonly string $configurationFile,
        private readonly string $clientKeysDirectory,
    ) {
    }

    public function load(): MockConfiguration
    {
        return $this->configuration ??= $this->read();
    }

    private function read(): MockConfiguration
    {
        $root = YamlNode::fromFile(Paths::resolve($this->projectDir, $this->configurationFile));
        $root->allowOnly([
            'issuer', 'token_endpoint_auth_methods_supported', 'messages', 'status_response', 'lifetimes',
            'clock_skew_seconds', 'max_client_assertion_lifetime_seconds', 'stale_auth_time_seconds',
            'timeout_delay_seconds', 'pairwise_salt', 'clients',
        ]);

        $issuer = $root->get('issuer')->string();
        if (!str_starts_with($issuer, 'https://') || str_ends_with($issuer, '/')) {
            throw $root->get('issuer')->error('must be an https URL without a trailing slash');
        }

        $messages = $root->get('messages');
        $messages->allowOnly([
            'envelope_issuer', 'statement_issuer', 'statement_claim', 'loa_authn', 'loa_dezi', 'json_schema',
        ]);
        $status = $root->get('status_response');
        $status->allowOnly(['id_field', 'status_field', 'revoked_at_field', 'active', 'revoked', 'other']);
        $lifetimes = $root->get('lifetimes');
        $lifetimes->allowOnly([
            'authorization_request_seconds', 'session_seconds', 'code_seconds', 'access_token_seconds',
            'id_token_seconds', 'envelope_seconds', 'statement_seconds',
        ]);

        $methods = $root->get('token_endpoint_auth_methods_supported')->stringList();
        $clients = [];
        foreach ($root->get('clients')->children() as $clientId => $client) {
            $clients[$clientId] = $this->client($clientId, $client);
        }
        if ($clients === []) {
            throw $root->get('clients')->error('must register at least one client');
        }

        return new MockConfiguration(
            issuer: $issuer,
            tokenEndpointAuthMethods: $methods,
            envelopeIssuer: $messages->get('envelope_issuer')->string(),
            statementIssuer: $messages->get('statement_issuer')->string(),
            statementClaim: $messages->get('statement_claim')->string(),
            loaAuthn: $messages->get('loa_authn')->string(),
            loaDezi: $messages->get('loa_dezi')->string(),
            jsonSchema: $messages->get('json_schema')->string(),
            statusNames: new StatusResponseNames(
                $status->get('id_field')->string(),
                $status->get('status_field')->string(),
                $status->get('revoked_at_field')->string(),
                $status->get('active')->string(),
                $status->get('revoked')->string(),
                $status->get('other')->string(),
            ),
            authorizationRequestSeconds: $lifetimes->get('authorization_request_seconds')->positiveInt(),
            sessionSeconds: $lifetimes->get('session_seconds')->positiveInt(),
            codeSeconds: $lifetimes->get('code_seconds')->positiveInt(),
            accessTokenSeconds: $lifetimes->get('access_token_seconds')->positiveInt(),
            idTokenSeconds: $lifetimes->get('id_token_seconds')->positiveInt(),
            envelopeSeconds: $lifetimes->get('envelope_seconds')->positiveInt(),
            statementSeconds: $lifetimes->get('statement_seconds')->positiveInt(),
            clockSkewSeconds: $root->get('clock_skew_seconds')->positiveInt(),
            maxClientAssertionLifetimeSeconds: $root->get('max_client_assertion_lifetime_seconds')->positiveInt(),
            staleAuthTimeSeconds: $root->get('stale_auth_time_seconds')->positiveInt(),
            timeoutDelaySeconds: $root->get('timeout_delay_seconds')->positiveInt(),
            pairwiseSalt: $root->get('pairwise_salt')->string(),
            clients: $clients,
        );
    }

    private function client(string $clientId, YamlNode $node): ClientRegistration
    {
        $node->allowOnly([
            'redirect_uris', 'authentication', 'signing_certificates', 'encryption_certificate', 'encryption_kid',
            'envelope_audience', 'sector_identifier',
        ]);
        $authentication = $node->get('authentication')->choice([
            ClientRegistration::AUTHENTICATION_PRIVATE_KEY_JWT,
            ClientRegistration::AUTHENTICATION_NONE,
        ]);
        $signing = [];
        foreach ($node->get('signing_certificates')->stringList() as $file) {
            $signing[] = $this->certificate($node->get('signing_certificates'), $file);
        }
        if (($authentication === ClientRegistration::AUTHENTICATION_PRIVATE_KEY_JWT) === ($signing === [])) {
            throw $node->get('signing_certificates')->error(
                'private_key_jwt needs at least one signing certificate; none takes none',
            );
        }
        $redirectUris = $node->get('redirect_uris')->stringList();
        if ($redirectUris === []) {
            throw $node->get('redirect_uris')->error('must hold at least one URL');
        }

        $encryption = $this->certificate(
            $node->get('encryption_certificate'),
            $node->get('encryption_certificate')->string(),
        );

        return new ClientRegistration(
            clientId: $clientId,
            redirectUris: $redirectUris,
            authentication: $authentication,
            signingCertificates: $signing,
            encryptionCertificate: $encryption,
            encryptionKid: $node->get('encryption_kid')->nullableString()
                ?? JWKFactory::createFromCertificate($encryption)->thumbprint('sha256'),
            envelopeAudience: $node->get('envelope_audience')->string(),
            sectorIdentifier: $node->get('sector_identifier')->string(),
        );
    }

    private function certificate(YamlNode $node, string $file): string
    {
        $path = Paths::resolve(Paths::resolve($this->projectDir, $this->clientKeysDirectory), $file);
        $pem = @file_get_contents($path);
        if ($pem === false) {
            throw $node->error(sprintf('cannot read certificate %s (run jip/bin/init-mock-keys)', $path));
        }
        try {
            JWKFactory::createFromCertificate($pem);
        } catch (Throwable $exception) {
            throw $node->error(sprintf('%s is not a usable certificate: %s', $path, $exception->getMessage()));
        }

        return $pem;
    }
}
