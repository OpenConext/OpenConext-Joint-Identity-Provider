<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp\Tests;

use DOMDocument;
use InvalidArgumentException;
use JointIdentityProvider\TestSp\Configuration;
use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Settings;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\TestCase;

final class ConfigurationTest extends TestCase
{
    private static string $certificateFile;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $csrKey = $key;
        $csr = openssl_csr_new(['commonName' => 'test'], $csrKey);
        self::assertInstanceOf(OpenSSLCertificateSigningRequest::class, $csr);
        $certificate = openssl_csr_sign($csr, null, $key, 1);
        self::assertNotFalse($certificate);
        self::assertTrue(openssl_x509_export($certificate, $pem));
        self::$certificateFile = (string) tempnam(sys_get_temp_dir(), 'jip-test-sp-');
        file_put_contents(self::$certificateFile, $pem);
        putenv('TEST_SP_IDP_CERTIFICATE_FILE=' . self::$certificateFile);
    }

    public static function tearDownAfterClass(): void
    {
        putenv('TEST_SP_IDP_CERTIFICATE_FILE');
        unlink(self::$certificateFile);
    }

    public function testLoginRequestCarriesNoStepupTrigger(): void
    {
        $configuration = Configuration::load(dirname(__DIR__) . '/config/test-sp.php');
        $request = new AuthnRequest(new Settings($configuration->saml));

        $document = new DOMDocument();
        self::assertTrue($document->loadXML($request->getXML()));

        self::assertSame(
            0,
            $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'RequestedAuthnContext')->length,
        );
        self::assertFalse($document->documentElement?->hasAttribute('ForceAuthn') ?? true);
    }

    public function testResponsesMustBeSignedAndSolicited(): void
    {
        $security = (new Settings(Configuration::load(dirname(__DIR__) . '/config/test-sp.php')->saml))
            ->getSecurityData();

        self::assertTrue($security['wantAssertionsSigned']);
        self::assertTrue($security['rejectUnsolicitedResponsesWithInResponseTo']);
        self::assertTrue($security['destinationStrictlyMatches']);
        self::assertTrue($security['rejectDeprecatedAlgorithm']);
        self::assertFalse($security['requestedAuthnContext']);
    }

    public function testUnreadableCertificateIsRefused(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'jip-test-sp-config-');
        $config = require dirname(__DIR__) . '/config/test-sp.php';
        self::assertIsArray($config);
        $config['idp_certificate_file'] = '/nonexistent';
        file_put_contents($file, sprintf('<?php return %s;', var_export($config, true)));

        try {
            $this->expectException(InvalidArgumentException::class);
            Configuration::load($file);
        } finally {
            unlink($file);
        }
    }
}
