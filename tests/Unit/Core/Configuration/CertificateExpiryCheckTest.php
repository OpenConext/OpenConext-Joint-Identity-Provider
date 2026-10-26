<?php

declare(strict_types=1);

namespace JointIdentityProvider\Tests\Unit\Core\Configuration;

use JointIdentityProvider\Core\Configuration\CertificateExpiryCheck;
use JointIdentityProvider\Core\Configuration\JipConfiguration;
use JointIdentityProvider\Tests\Support\ConfigurationFixture;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The certificate expiry alert (design §14, §18 "Client keys"); expiry never stops JIP from starting.
 */
final class CertificateExpiryCheckTest extends TestCase
{
    private ConfigurationFixture $fixture;
    private JipConfiguration $configuration;

    protected function setUp(): void
    {
        $this->fixture = new ConfigurationFixture();
        ConfigurationFixture::setEnv('EB_API_TOKEN', ConfigurationFixture::API_TOKEN);

        // The fixture's certificates are valid for 365 days; the warning window is 60 days.
        $this->configuration = ConfigurationFixture::loader(
            $this->fixture->writeConfiguration($this->fixture->mockConfiguration()),
        )->load();
    }

    protected function tearDown(): void
    {
        ConfigurationFixture::setEnv('EB_API_TOKEN', null);
        $this->fixture->remove();
    }

    public function test_certificates_outside_the_warning_window_are_ok(): void
    {
        $check = new CertificateExpiryCheck(new MockClock('+200 days'));

        self::assertSame([], $check->findings($this->configuration));
        self::assertSame(CertificateExpiryCheck::OK, $check->status($this->configuration));
    }

    public function test_certificates_within_the_warning_window_are_expiring(): void
    {
        $check = new CertificateExpiryCheck(new MockClock('+340 days'));

        self::assertSame(
            [
                'provider.clients.ggd.signing_key' => CertificateExpiryCheck::EXPIRING,
                'provider.clients.ggd.decryption_keys[0]' => CertificateExpiryCheck::EXPIRING,
            ],
            $check->findings($this->configuration),
        );
        self::assertSame(CertificateExpiryCheck::EXPIRING, $check->status($this->configuration));
    }

    public function test_expired_certificates_are_reported(): void
    {
        $check = new CertificateExpiryCheck(new MockClock('+400 days'));

        self::assertSame(CertificateExpiryCheck::EXPIRED, $check->status($this->configuration));
        self::assertCount(2, $check->findings($this->configuration));
    }

    public function test_an_expired_certificate_does_not_stop_jip_from_starting(): void
    {
        $expired = $this->fixture->writeKeyPair('expired', days: 0);
        $configuration = ConfigurationFixture::with(
            $this->fixture->mockConfiguration(),
            ['provider', 'clients', 'ggd', 'decryption_keys', 0],
            ['certificate' => $expired . '.crt', 'private_key' => $expired . '.pem'],
        );

        $loaded = ConfigurationFixture::loader($this->fixture->writeConfiguration($configuration))->load();

        self::assertSame(
            ['provider.clients.ggd.decryption_keys[0]' => CertificateExpiryCheck::EXPIRED],
            (new CertificateExpiryCheck(new MockClock('+1 minute')))->findings($loaded),
        );
    }
}
