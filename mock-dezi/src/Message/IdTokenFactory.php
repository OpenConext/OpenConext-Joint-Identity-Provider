<?php

declare(strict_types=1);

namespace MockDezi\Message;

use MockDezi\Configuration\ClientRegistration;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Fixture\Person;
use MockDezi\Key\KeyRing;
use MockDezi\Key\MessageType;
use MockDezi\Scenario\Scenario;
use MockDezi\Store\Record\AuthorizationCode;

/**
 * The RS256 ID token, signed with the ID-token key that /openid/connect/jwks.json publishes (design §14).
 */
final readonly class IdTokenFactory
{
    public function __construct(
        private KeyRing $keys,
    ) {
    }

    public static function pairwiseSubject(
        MockConfiguration $configuration,
        ClientRegistration $client,
        Person $person,
    ): string {
        return Jose::base64Url(hash_hmac(
            'sha256',
            $client->sectorIdentifier . '|' . $person->deziNummer,
            $configuration->pairwiseSalt,
            true,
        ));
    }

    public function create(
        MockConfiguration $configuration,
        ClientRegistration $client,
        AuthorizationCode $code,
        string $subject,
        int $now,
    ): string {
        $scenario = $code->scenario;
        $claims = [
            'iss' => $configuration->issuer,
            'sub' => $subject,
            'aud' => $client->clientId,
            'iat' => $now,
            'exp' => $now + $configuration->idTokenSeconds,
            'auth_time' => match ($scenario) {
                Scenario::StaleAuthTime => $code->attemptReceivedAt - $configuration->staleAuthTimeSeconds,
                Scenario::FutureAuthTime => $now + 600,
                default => $code->authTime,
            },
            'nonce' => $scenario === Scenario::IdTokenWrongNonce ? Jose::randomToken() : $code->nonce,
        ];

        switch ($scenario) {
            case Scenario::IdTokenWrongIssuer:
                $claims['iss'] = $configuration->issuer . '/wrong-issuer';
                break;
            case Scenario::IdTokenWrongAudience:
                $claims['aud'] = 'another-client';
                break;
            case Scenario::IdTokenExtraAudience:
                $claims['aud'] = [$client->clientId, 'untrusted-audience'];
                break;
            case Scenario::IdTokenExpired:
                $claims['iat'] = $now - 900;
                $claims['exp'] = $now - 600;
                break;
            case Scenario::IdTokenWithoutAuthTime:
                unset($claims['auth_time']);
                break;
            case Scenario::IdTokenWithoutSub:
                unset($claims['sub']);
                break;
            default:
                break;
        }
        $header = ['typ' => 'JWT', 'kid' => $this->keys->kid(MessageType::IdToken)];

        return match ($scenario) {
            Scenario::IdTokenAlgNone => Jose::unsigned($claims),
            Scenario::IdTokenBadSignature => Jose::sign($claims, $this->keys->roguePrivateKey(), $header),
            Scenario::IdTokenUnknownKid => Jose::sign(
                $claims,
                $this->keys->roguePrivateKey(),
                ['kid' => KeyRing::UNKNOWN_KID] + $header,
            ),
            Scenario::IdTokenSignedWithStatementKey => Jose::sign(
                $claims,
                $this->keys->privateKey(MessageType::Statement),
                ['kid' => $this->keys->kid(MessageType::Statement)] + $header,
            ),
            default => Jose::sign($claims, $this->keys->privateKey(MessageType::IdToken), $header),
        };
    }
}
