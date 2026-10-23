<?php

declare(strict_types=1);

namespace JointIdentityProvider\TestSp\Tests;

use DOMDocument;
use InvalidArgumentException;
use JointIdentityProvider\TestSp\Application;
use JointIdentityProvider\TestSp\Configuration;
use OneLogin\Saml2\Utils;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class ApplicationTest extends TestCase
{
    private const string BASE = 'https://jip-test-sp.dev.openconext.local/';
    private const string ISSUER = 'https://engine.dev.openconext.local/authentication/idp/metadata';

    private string $directory;
    private string $key;
    private string $certificate;
    private Application $application;

    protected function setUp(): void
    {
        // Isolate real PHP sessions and headers in a separate process for every case.
        $directory = tempnam(sys_get_temp_dir(), 'jip-sp-application-');
        self::assertNotFalse($directory);
        unlink($directory);
        self::assertTrue(mkdir($directory, 0700));
        $this->directory = $directory;
        ini_set('session.save_path', $directory);
        ini_set('error_log', $directory . '/error.log');
        ob_start();

        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        self::assertNotFalse($key);
        self::assertTrue(openssl_pkey_export($key, $keyPem));
        self::assertIsString($keyPem);
        $this->key = $keyPem;
        $csrKey = $key;
        $csr = openssl_csr_new(['commonName' => 'test-sp-test'], $csrKey);
        self::assertInstanceOf(OpenSSLCertificateSigningRequest::class, $csr);
        $certificate = openssl_csr_sign($csr, null, $key, 1);
        self::assertNotFalse($certificate);
        self::assertTrue(openssl_x509_export($certificate, $certificatePem));
        self::assertIsString($certificatePem);
        $this->certificate = $certificatePem;
        file_put_contents($directory . '/idp.crt', $this->certificate);
        putenv('TEST_SP_IDP_CERTIFICATE_FILE=' . $directory . '/idp.crt');
        $this->application = new Application(Configuration::load(dirname(__DIR__) . '/config/test-sp.php'));
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['HTTP_HOST'] = 'jip-test-sp.dev.openconext.local';
        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['SCRIPT_NAME'] = '/index.php';
        $_POST = [];
        $_COOKIE = [];
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        $files = glob($this->directory . '/*');
        foreach ($files === false ? [] : $files as $file) {
            unlink($file);
        }
        rmdir($this->directory);
        putenv('TEST_SP_IDP_CERTIFICATE_FILE');
        ob_end_clean();
    }

    public function testConfigurationFailureLogsTheSettingAndKeepsTheResponseGeneric(): void
    {
        $missingCertificate = $this->directory . '/private-mount-path.crt';
        putenv('TEST_SP_IDP_CERTIFICATE_FILE=' . $missingCertificate);
        ob_start();
        require dirname(__DIR__) . '/public/index.php';
        $body = ob_get_clean();

        self::assertSame(500, http_response_code());
        self::assertSame('Internal error', $body);
        $log = file_get_contents($this->directory . '/error.log');
        self::assertIsString($log);
        self::assertStringContainsString(
            'configuration error: idp_certificate_file is not a readable X.509 certificate.',
            $log,
        );
        self::assertStringNotContainsString($missingCertificate, $log);
    }

    public function testRuntimeValidationFailureDoesNotLogReceivedValues(): void
    {
        ob_start();
        Application::failSafe(new InvalidArgumentException('secret-saml-content'));
        $body = ob_get_clean();

        self::assertSame(500, http_response_code());
        self::assertSame('Internal error', $body);
        $log = file_get_contents($this->directory . '/error.log');
        self::assertIsString($log);
        self::assertStringContainsString('internal error (InvalidArgumentException) at ApplicationTest.php:', $log);
        self::assertStringNotContainsString('secret-saml-content', $log);
    }

    public function testHealthAndUnknownRouteDoNotStartSessions(): void
    {
        self::assertSame('UP', $this->request('GET', '/health'));
        self::assertSame(200, http_response_code());
        self::assertSame('Not found', $this->request('POST', '/login'));
        self::assertSame(404, http_response_code());
        self::assertSame(PHP_SESSION_NONE, session_status());
    }

    public function testLoginStartsAPendingRequestAndClearsThePreviousResult(): void
    {
        self::assertStringContainsString('Not logged in', $this->request('GET', '/'));
        $_SESSION['result'] = ['access' => 'dezi'];
        $this->request('GET', '/login');

        self::assertSame(302, http_response_code());
        self::assertArrayHasKey('pending_request_id', $_SESSION);
        self::assertIsString($_SESSION['pending_request_id']);
        self::assertStringStartsWith('ONELOGIN_', $_SESSION['pending_request_id']);
        self::assertArrayNotHasKey('result', $_SESSION);
        self::assertSame('jip_test_sp', session_name());
        $cookie = session_get_cookie_params();
        self::assertTrue($cookie['secure']);
        self::assertTrue($cookie['httponly']);
        self::assertSame('Lax', $cookie['samesite']);
    }

    public function testSignedResponseRenewsSessionAndCannotBeReplayed(): void
    {
        $this->request('GET', '/login');
        $oldSession = session_id();
        $_POST['SAMLResponse'] = base64_encode($this->response());
        $this->request('POST', '/saml/acs');

        self::assertSame(303, http_response_code());
        self::assertNotSame($oldSession, session_id());
        self::assertFileDoesNotExist($this->directory . '/sess_' . $oldSession);
        self::assertArrayNotHasKey('pending_request_id', $_SESSION);
        $result = $_SESSION['result'];
        self::assertIsArray($result);
        self::assertSame('dezi', $result['access']);
        self::assertSame('_response', $result['response_id']);
        $home = $this->request('GET', '/');
        self::assertStringContainsString('900000001', $home);
        self::assertStringContainsString('&lt;Organisation&gt;', $home);
        self::assertStringNotContainsString('<Organisation>', $home);

        $this->request('POST', '/saml/acs');
        self::assertSame(400, http_response_code());
    }

    /** @return iterable<string, array{string, string}> */
    public static function multiValueResponses(): iterable
    {
        yield 'verified and skipped' => ['both-flags', 'the login flag has more than one value'];
        yield 'two role codes' => ['two-roles', 'the role code is malformed or has more than one value'];
    }

    #[DataProvider('multiValueResponses')]
    public function testSignedMultiValueAttributesAreRefused(string $mode, string $reason): void
    {
        $this->request('GET', '/login');
        $_POST['SAMLResponse'] = base64_encode($this->response($mode));
        $this->request('POST', '/saml/acs');

        self::assertSame(303, http_response_code());
        $result = $_SESSION['result'];
        self::assertIsArray($result);
        self::assertSame('refused', $result['access']);
        self::assertSame($reason, $result['reason']);
        self::assertArrayNotHasKey('pending_request_id', $_SESSION);
    }

    public function testResponseWithoutPendingLoginIsRefused(): void
    {
        $_POST['SAMLResponse'] = 'not-a-response';
        self::assertStringContainsString('No login is pending', $this->request('POST', '/saml/acs'));
        self::assertSame(400, http_response_code());
        self::assertArrayNotHasKey('result', $_SESSION);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidResponses(): iterable
    {
        yield 'malformed XML' => ['malformed'];
        yield 'DOCTYPE' => ['doctype'];
        yield 'wrong request' => ['wrong-request'];
        yield 'expired assertion' => ['expired'];
        yield 'unsigned assertion' => ['unsigned'];
        yield 'tampered assertion' => ['tampered'];
    }

    #[DataProvider('invalidResponses')]
    public function testInvalidResponseConsumesPendingLoginWithoutGrantingAccess(string $mode): void
    {
        $this->request('GET', '/login');
        $_POST['SAMLResponse'] = base64_encode($mode === 'malformed' ? '<broken' : $this->response($mode));
        self::assertStringContainsString('Response not accepted', $this->request('POST', '/saml/acs'));
        self::assertContains(http_response_code(), [400, 403]);
        self::assertArrayNotHasKey('pending_request_id', $_SESSION);
        self::assertArrayNotHasKey('result', $_SESSION);
        self::assertStringContainsString('Not logged in', $this->request('GET', '/'));
    }

    public function testLogoutDestroysTheAuthenticatedSession(): void
    {
        $this->request('GET', '/login');
        $_POST['SAMLResponse'] = base64_encode($this->response());
        $this->request('POST', '/saml/acs');
        self::assertArrayHasKey('result', $_SESSION);
        $sessionFile = $this->directory . '/sess_' . session_id();

        $this->request('POST', '/logout');
        self::assertSame(303, http_response_code());
        self::assertSame([], $_SESSION);
        self::assertSame(PHP_SESSION_NONE, session_status());
        self::assertFileDoesNotExist($sessionFile);
        self::assertStringContainsString('Not logged in', $this->request('GET', '/'));
    }

    private function request(string $method, string $path): string
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['REQUEST_URI'] = $path;
        http_response_code(200);
        ob_start();
        $this->application->handle($method, $path);
        $body = ob_get_clean();
        self::assertNotFalse($body);

        return $body;
    }

    private function response(string $mode = 'valid'): string
    {
        $request = $_SESSION['pending_request_id'];
        self::assertIsString($request);
        if ($mode === 'wrong-request') {
            $request = '_other_request';
        }
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $expiry = gmdate('Y-m-d\TH:i:s\Z', time() + ($mode === 'expired' ? -3600 : 300));
        $audience = self::BASE . 'saml/metadata';
        $acs = self::BASE . 'saml/acs';
        $issuer = self::ISSUER;
        $attributes = '';
        $values = [
            'dezi:login' => 'verified',
            'dezi:dezi-nummer' => '900000001',
            'dezi:abonnee-nummer' => '90000001',
            'dezi:rol-code' => '01.000',
            'organisation' => '&lt;Organisation&gt;',
        ];
        if ($mode === 'both-flags') {
            $values['dezi:login'] = ['verified', 'skipped'];
        }
        if ($mode === 'two-roles') {
            $values['dezi:rol-code'] = ['01.000', '00.000'];
        }
        foreach ($values as $name => $value) {
            $attributes .= '<saml:Attribute Name="urn:mace:govroam.nl:attribute-def:' . $name . '">';
            foreach ((array) $value as $item) {
                $attributes .= '<saml:AttributeValue>' . $item . '</saml:AttributeValue>';
            }
            $attributes .= '</saml:Attribute>';
        }
        $assertion = <<<XML
            <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="$now">
              <saml:Issuer>$issuer</saml:Issuer>
              <saml:Subject>
                <saml:NameID>test-person</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                  <saml:SubjectConfirmationData InResponseTo="$request" Recipient="$acs" NotOnOrAfter="$expiry"/>
                </saml:SubjectConfirmation>
              </saml:Subject>
              <saml:Conditions NotOnOrAfter="$expiry">
                <saml:AudienceRestriction><saml:Audience>$audience</saml:Audience></saml:AudienceRestriction>
              </saml:Conditions>
              <saml:AuthnStatement AuthnInstant="$now" SessionIndex="_session">
                <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
              </saml:AuthnStatement>
              <saml:AttributeStatement>$attributes</saml:AttributeStatement>
            </saml:Assertion>
            XML;
        if ($mode !== 'unsigned') {
            $document = new DOMDocument();
            self::assertTrue($document->loadXML(Utils::addSign($assertion, $this->key, $this->certificate)));
            // Assertion schema places Signature after Issuer. Moving the enveloped signature preserves its digest.
            $signature = $document->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
            $issuerNode = $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);
            self::assertNotNull($signature);
            self::assertNotNull($issuerNode);
            self::assertNotNull($document->documentElement);
            $document->documentElement->insertBefore($signature, $issuerNode->nextSibling);
            $assertion = $document->saveXML($document->documentElement);
            self::assertNotFalse($assertion);
        }
        if ($mode === 'tampered') {
            $assertion = str_replace('900000001', '900000099', $assertion);
        }

        return ($mode === 'doctype' ? '<!DOCTYPE samlp:Response>' : '') . <<<XML
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response" Version="2.0" IssueInstant="$now" Destination="$acs" InResponseTo="$request">
              <saml:Issuer>$issuer</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
              $assertion
            </samlp:Response>
            XML;
    }
}
