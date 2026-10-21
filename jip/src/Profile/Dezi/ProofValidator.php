<?php

declare(strict_types=1);

namespace JointIdentityProvider\Profile\Dezi;

use DateTimeImmutable;
use JointIdentityProvider\Core\Configuration\ProviderConfiguration;
use JointIdentityProvider\Oidc\AuthenticatedLogin;
use JointIdentityProvider\Oidc\Jose\SignedMessageVerifier;
use JointIdentityProvider\Oidc\Jose\VerifiedMessage;
use JointIdentityProvider\Oidc\OidcFailure;
use JointIdentityProvider\Oidc\OidcFailureType;
use LogicException;
use SensitiveParameter;

/**
 * Validates DEZI's envelope and the sealed statement inside it (design §14, §16). Expected values come
 * from the client registration and the approved configuration, never from the messages. Identifiers stay
 * strings exactly as DEZI sent them; nothing is trimmed, converted or filled in.
 */
final readonly class ProofValidator
{
    public const string ENVELOPE = 'envelope';
    public const string STATEMENT = 'statement';

    // Statement claims that may be released (design §6). Technical claims such as loa_dezi and
    // verklaring_id are validated here and never released.
    public const array RELEASABLE_CLAIMS = [
        'dezi_nummer',
        'abonnee_nummer',
        'rol_code',
        'rol_naam',
        'abonnee_naam',
        'voorletters',
        'voorvoegsel',
        'achternaam',
    ];

    // Always non-empty strings; null never stands in for them (design §14).
    public const array REQUIRED_CLAIMS = ['dezi_nummer', 'abonnee_nummer'];

    private const string UUID = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';

    public function __construct(private SignedMessageVerifier $verifier)
    {
    }

    /**
     * @throws DeziFailure for a failed check of the envelope or the statement
     * @throws OidcFailure when no usable key for the message type is available
     */
    public function validate(
        #[SensitiveParameter] string $envelopeJws,
        AuthenticatedLogin $login,
        ProviderConfiguration $provider,
        DeziProfileConfiguration $configuration,
        DateTimeImmutable $now,
    ): VerifiedProof {
        $nowSeconds = (float) $now->format('U.u');
        $skew = $provider->clockSkewSeconds;

        $envelope = $this->verify($envelopeJws, $provider, self::ENVELOPE, DeziFailureType::EnvelopeInvalid)->claims;
        $envelopeFailure = static fn (string $detail): DeziFailure => new DeziFailure(
            DeziFailureType::EnvelopeInvalid,
            'envelope: ' . $detail,
        );

        if (($envelope['iss'] ?? null) !== $provider->expectedIssuers[self::ENVELOPE]) {
            throw $envelopeFailure('iss differs from provider.expected_issuers.envelope');
        }
        $audience = $configuration->envelopeAudiences[$login->client->name]
            ?? throw new LogicException('The client has no configured envelope audience.');
        if (($envelope['aud'] ?? null) !== $audience && ($envelope['aud'] ?? null) !== [$audience]) {
            throw $envelopeFailure('aud is not exactly the audience configured for this client');
        }
        $issuedAt = self::time($envelope, 'iat', $envelopeFailure);
        $envelopeExpiry = self::time($envelope, 'exp', $envelopeFailure);
        if ($issuedAt > $nowSeconds + $skew) {
            throw $envelopeFailure('iat lies in the future');
        }
        if (
            array_key_exists('nbf', $envelope)
            && self::time($envelope, 'nbf', $envelopeFailure) > $nowSeconds + $skew
        ) {
            throw $envelopeFailure('nbf lies in the future');
        }
        // The hard expiry bounds delivery, so the clock skew never extends it.
        if ($envelopeExpiry <= $nowSeconds) {
            throw $envelopeFailure('exp has passed');
        }
        self::checkSubject($envelope, $login->idToken->subject, $configuration->subjectAssociation);
        if (($envelope['loa_authn'] ?? null) !== $configuration->expectedLoaAuthn) {
            throw $envelopeFailure('loa_authn is not the configured high-assurance value');
        }
        $verklaringId = $envelope['verklaring_id'] ?? null;
        if (!is_string($verklaringId) || $verklaringId === '') {
            throw $envelopeFailure('verklaring_id is missing');
        }
        $statementJws = $envelope[$configuration->statementClaim] ?? null;
        if (!is_string($statementJws) || $statementJws === '') {
            throw $envelopeFailure('the configured statement claim is missing');
        }

        $statementMessage = $this->verify($statementJws, $provider, self::STATEMENT, DeziFailureType::StatementInvalid);
        $statement = $statementMessage->claims;
        $statementFailure = static fn (string $detail): DeziFailure => new DeziFailure(
            DeziFailureType::StatementInvalid,
            'statement: ' . $detail,
        );

        if (($statementMessage->header['jku'] ?? null) !== $provider->approvedKeyAddresses[self::STATEMENT]) {
            throw $statementFailure('jku is not the approved key address');
        }
        if (($statement['iss'] ?? null) !== $provider->expectedIssuers[self::STATEMENT]) {
            throw $statementFailure('iss differs from provider.expected_issuers.statement');
        }
        $notBefore = self::time($statement, 'nbf', $statementFailure);
        $statementExpiry = self::time($statement, 'exp', $statementFailure);
        if ($notBefore > $nowSeconds + $skew) {
            throw $statementFailure('nbf lies in the future');
        }
        if ($statementExpiry <= $nowSeconds) {
            throw $statementFailure('exp has passed');
        }
        $statementId = $statement['verklaring_id'] ?? null;
        if (!is_string($statementId) || preg_match(self::UUID, $statementId) !== 1) {
            throw $statementFailure('verklaring_id is not a UUID');
        }
        if ($statementId !== $verklaringId) {
            throw $statementFailure('verklaring_id differs from the envelope');
        }
        if (($statement['loa_dezi'] ?? null) !== $configuration->expectedLoaDezi) {
            throw $statementFailure('loa_dezi is not the configured high-assurance value');
        }

        $claims = self::releasableClaims($statement, $configuration->nullableClaims, $statementFailure);
        $hardExpiry = self::dateTime(min($envelopeExpiry, $statementExpiry))
            ?? throw $statementFailure('exp is out of range');

        return new VerifiedProof($claims, $verklaringId, $hardExpiry);
    }

    /**
     * @throws DeziFailure|OidcFailure
     */
    private function verify(
        string $compact,
        ProviderConfiguration $provider,
        string $messageType,
        DeziFailureType $invalid,
    ): VerifiedMessage {
        try {
            return $this->verifier->verify($compact, $provider, $messageType, OidcFailureType::MessageInvalid);
        } catch (OidcFailure $failure) {
            if ($failure->type === OidcFailureType::MessageInvalid) {
                throw new DeziFailure($invalid, $failure->detail, $failure);
            }

            throw $failure;
        }
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private static function checkSubject(
        array $envelope,
        #[SensitiveParameter] string $idTokenSubject,
        SubjectAssociation $association,
    ): void {
        if (array_key_exists('sub', $envelope)) {
            $subject = $envelope['sub'];
            if (!is_string($subject) || !hash_equals($idTokenSubject, $subject)) {
                throw new DeziFailure(DeziFailureType::EnvelopeInvalid, 'envelope: sub differs from the ID token sub');
            }

            return;
        }

        if ($association === SubjectAssociation::EnvelopeSub) {
            throw new DeziFailure(DeziFailureType::EnvelopeInvalid, 'envelope: sub is missing');
        }
    }

    /**
     * @param array<string, mixed> $statement
     * @param list<string> $nullableClaims
     * @param callable(string): DeziFailure $failure
     * @return array<string, list<string>>
     */
    private static function releasableClaims(array $statement, array $nullableClaims, callable $failure): array
    {
        $claims = [];
        foreach (self::RELEASABLE_CLAIMS as $name) {
            $required = in_array($name, self::REQUIRED_CLAIMS, true);
            if (!array_key_exists($name, $statement)) {
                if ($required) {
                    throw $failure($name . ' is missing');
                }
                continue;
            }

            $value = $statement[$name];
            if ($value === null && !$required && in_array($name, $nullableClaims, true)) {
                continue;
            }
            if ($value === null) {
                throw $failure($name . ' is null, which is not permitted for it');
            }
            if (!is_string($value) || $value === '') {
                throw $failure($name . ' is not a non-empty string');
            }
            // A literal "null" is an unapproved null shape; it never silently becomes absent.
            if ($value === 'null') {
                throw $failure($name . ' is the string "null"');
            }

            $claims[$name] = [$value];
        }

        return $claims;
    }

    /**
     * A time claim must be a JSON number (design §16).
     *
     * @param array<string, mixed> $claims
     * @param callable(string): DeziFailure $failure
     */
    private static function time(array $claims, string $name, callable $failure): float
    {
        $value = $claims[$name] ?? null;
        if ((!is_int($value) && !is_float($value)) || !is_finite((float) $value) || $value < 0) {
            throw $failure($name . ' is missing or not a number');
        }

        return (float) $value;
    }

    private static function dateTime(float $seconds): ?DateTimeImmutable
    {
        if ($seconds >= PHP_INT_MAX / 1_000_000) {
            return null;
        }
        $time = DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $seconds));

        return $time === false ? null : $time;
    }
}
