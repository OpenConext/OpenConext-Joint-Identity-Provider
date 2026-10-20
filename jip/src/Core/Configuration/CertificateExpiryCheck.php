<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use DateInterval;
use Psr\Clock\ClockInterface;

/**
 * The certificate expiry alert (design §14): client certificates within
 * provider.certificate_expiry_warning_days of expiry, or expired. Expiry alone never stops JIP.
 */
final readonly class CertificateExpiryCheck
{
    public const string OK = 'ok';
    public const string EXPIRING = 'expiring';
    public const string EXPIRED = 'expired';

    public function __construct(private ClockInterface $clock)
    {
    }

    /**
     * @return array<string, string> configuration path of the key entry => EXPIRING or EXPIRED
     */
    public function findings(JipConfiguration $configuration): array
    {
        $now = $this->clock->now();
        $warningDays = $configuration->provider->certificateExpiryWarningDays;
        $warnFrom = $now->add(new DateInterval(sprintf('P%dD', $warningDays)));

        $findings = [];
        foreach ($configuration->clientKeyPairs() as $keyPair) {
            if ($keyPair->notAfter <= $now) {
                $findings[$keyPair->configPath] = self::EXPIRED;
            } elseif ($keyPair->notAfter <= $warnFrom) {
                $findings[$keyPair->configPath] = self::EXPIRING;
            }
        }

        return $findings;
    }

    public function status(JipConfiguration $configuration): string
    {
        $findings = $this->findings($configuration);

        if (in_array(self::EXPIRED, $findings, true)) {
            return self::EXPIRED;
        }

        return $findings === [] ? self::OK : self::EXPIRING;
    }
}
