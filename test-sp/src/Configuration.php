<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp;

use InvalidArgumentException;
use OneLogin\Saml2\Constants;

/**
 * The test SP's settings: its SAML identity, EngineBlock as its only IdP, and the access rules of design §7.
 */
final readonly class Configuration
{
    /**
     * @param array<string, mixed> $saml settings for onelogin/php-saml
     */
    private function __construct(public array $saml, public AccessRules $rules, public string $baseUrl)
    {
    }

    public static function load(string $file): self
    {
        $config = require $file;
        if (!is_array($config)) {
            throw new InvalidArgumentException('The configuration file must return an array.');
        }

        $baseUrl = self::string($config, 'base_url');
        if (preg_match('#^https://[^/?\#]+/$#', $baseUrl) !== 1) {
            throw new InvalidArgumentException('base_url must be an https URL ending in a slash, without a path.');
        }
        $certificateFile = self::string($config, 'idp_certificate_file');
        $certificate = is_readable($certificateFile) ? file_get_contents($certificateFile) : false;
        if ($certificate === false || openssl_x509_read($certificate) === false) {
            throw new InvalidArgumentException('idp_certificate_file is not a readable X.509 certificate.');
        }
        $rules = $config['access_rules'] ?? null;
        if (!is_array($rules)) {
            throw new InvalidArgumentException('access_rules must be a map.');
        }

        return new self([
            'strict' => true,
            'debug' => false,
            'baseurl' => $baseUrl,
            'sp' => [
                'entityId' => self::string($config, 'sp_entity_id'),
                'assertionConsumerService' => [
                    'url' => $baseUrl . 'saml/acs',
                    'binding' => Constants::BINDING_HTTP_POST,
                ],
                'NameIDFormat' => Constants::NAMEID_UNSPECIFIED,
            ],
            'idp' => [
                'entityId' => self::string($config, 'idp_entity_id'),
                'singleSignOnService' => [
                    'url' => self::string($config, 'idp_sso_url'),
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'x509cert' => $certificate,
            ],
            'security' => [
                'authnRequestsSigned' => false,
                'wantMessagesSigned' => false,
                'wantAssertionsSigned' => true,
                'wantNameId' => true,
                // No RequestedAuthnContext: a Stepup level in the login request is one of EngineBlock's four
                // Stepup triggers, and after Stepup EngineBlock loses JIP's nonce (design §9 item 10, §17 check 7).
                'requestedAuthnContext' => false,
                'wantXMLValidation' => true,
                'destinationStrictlyMatches' => true,
                'rejectUnsolicitedResponsesWithInResponseTo' => true,
                'rejectDeprecatedAlgorithm' => true,
                'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
            ],
        ], AccessRules::fromArray($rules), $baseUrl);
    }

    /**
     * @param array<mixed> $config
     */
    private static function string(array $config, string $key): string
    {
        $value = $config[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException(sprintf('%s must be a non-empty string.', $key));
        }

        return $value;
    }
}
