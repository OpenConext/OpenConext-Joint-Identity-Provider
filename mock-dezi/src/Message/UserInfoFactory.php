<?php

declare(strict_types=1);

namespace MockDezi\Message;

use MockDezi\Configuration\ClientRegistration;
use MockDezi\Configuration\MockConfiguration;
use MockDezi\Fixture\Person;
use MockDezi\Fixture\Profile;
use MockDezi\Key\KeyRing;
use MockDezi\Key\MessageType;
use MockDezi\Scenario\Scenario;

/**
 * The UserInfo response (design §14): a JWE (RSA-OAEP, A256CBC-HS512) to the client's registered encryption
 * certificate, around the signed envelope, which carries the sealed statement.
 *
 * PROVISIONAL message shapes, after the design's description of specification v0.7: the claim names and types
 * below; the envelope has no `sub`; the statement carries `jku`, the envelope does not; the envelope claim that
 * carries the statement is `messages.statement_claim`. The CIBG's example messages decide them (design §10).
 */
final readonly class UserInfoFactory
{
    private const string WRONG_LOA = 'http://eidas.europa.eu/LoA/substantial';

    public function __construct(
        private KeyRing $keys,
    ) {
    }

    public function create(
        MockConfiguration $configuration,
        ClientRegistration $client,
        Person $person,
        Profile $profile,
        string $verklaringId,
        string $subject,
        Scenario $scenario,
        int $now,
    ): string {
        if ($scenario === Scenario::StatementVerklaringIdNotUuid) {
            $verklaringId = 'mock-not-a-uuid-' . substr(Jose::randomToken(), 0, 12);
        }
        $statement = $this->statement($configuration, $person, $profile, $verklaringId, $scenario, $now);
        $envelope = $this->envelope($configuration, $client, $verklaringId, $statement, $subject, $scenario, $now);
        if ($scenario === Scenario::UserInfoNotEncrypted) {
            return $envelope;
        }

        return Jose::encrypt(
            $envelope,
            $scenario === Scenario::UserInfoUnregisteredKey
                ? $this->keys->roguePublicKey()
                : $client->encryptionCertificate,
            $scenario === Scenario::UserInfoWrongKeyAlgorithm ? 'RSA-OAEP-256' : 'RSA-OAEP',
            $scenario === Scenario::UserInfoWrongContentEncryption ? 'A256GCM' : 'A256CBC-HS512',
            $scenario === Scenario::UserInfoUnknownKid ? 'mock-dezi-unknown-encryption-kid' : $client->encryptionKid,
        );
    }

    private function statement(
        MockConfiguration $configuration,
        Person $person,
        Profile $profile,
        string $verklaringId,
        Scenario $scenario,
        int $now,
    ): string {
        $claims = [
            'jti' => Jose::uuidV4(),
            'iss' => $configuration->statementIssuer,
            'nbf' => $now - 60,
            'exp' => $now + $configuration->statementSeconds,
            'json_schema' => $configuration->jsonSchema,
            'dezi_nummer' => $person->deziNummer,
            'voorletters' => $person->voorletters,
            'voorvoegsel' => $person->voorvoegsel,
            'achternaam' => $person->achternaam,
            'abonnee_nummer' => $profile->abonneeNummer,
            'abonnee_naam' => $profile->abonneeNaam,
        ];
        // A profile without a role sends no role claims (PROVISIONAL, design §16).
        if ($profile->rolCode !== null) {
            $claims['rol_code'] = $profile->rolCode;
            $claims['rol_naam'] = $profile->rolNaam;
            $claims['rol_code_bron'] = $profile->rolCodeBron;
        }
        $claims += [
            'loa_dezi' => $configuration->loaDezi,
            'verklaring_id' => $scenario === Scenario::StatementVerklaringIdMismatch ? Jose::uuidV4() : $verklaringId,
            // JIP never calls these links (design §15); they lead to a counting endpoint that refuses.
            'status_uri' => $configuration->url('/statement-link/status/' . rawurlencode($verklaringId)),
            'revocatie_controle_uri' => $configuration->url('/statement-link/revocatie/' . rawurlencode($verklaringId)),
        ];

        switch ($scenario) {
            case Scenario::StatementWrongIssuer:
                $claims['iss'] = 'wrong-' . $configuration->statementIssuer;
                break;
            case Scenario::StatementExpired:
                $claims['nbf'] = $now - 7200;
                $claims['exp'] = $now - 3600;
                break;
            case Scenario::StatementNotYetValid:
                $claims['nbf'] = $now + 3600;
                break;
            case Scenario::StatementTimeAsString:
                $claims['exp'] = (string) ($now + $configuration->statementSeconds);
                break;
            case Scenario::StatementWrongLoa:
                $claims['loa_dezi'] = self::WRONG_LOA;
                break;
            case Scenario::StatementNumericDeziNummer:
                $claims['dezi_nummer'] = (int) $person->deziNummer;
                break;
            case Scenario::StatementEmptyAbonneeNummer:
                $claims['abonnee_nummer'] = '';
                break;
            case Scenario::StatementDeziNummerNull:
                $claims['dezi_nummer'] = null;
                break;
            case Scenario::StatementRolCodeNull:
                $claims['rol_code'] = null;
                break;
            case Scenario::StatementVoorvoegselStringNull:
                $claims['voorvoegsel'] = 'null';
                break;
            default:
                break;
        }

        $statementJku = $configuration->url(MessageType::Statement->jwksPath());
        $header = ['kid' => $this->keys->kid(MessageType::Statement), 'jku' => $statementJku];

        return match ($scenario) {
            Scenario::StatementBadSignature => Jose::sign($claims, $this->keys->roguePrivateKey(), $header),
            Scenario::StatementUnknownKid => Jose::sign(
                $claims,
                $this->keys->roguePrivateKey(),
                ['kid' => KeyRing::UNKNOWN_KID] + $header,
            ),
            Scenario::StatementSignedWithIdTokenKey => Jose::sign(
                $claims,
                $this->keys->privateKey(MessageType::IdToken),
                ['kid' => $this->keys->kid(MessageType::IdToken)] + $header,
            ),
            Scenario::StatementJkuOtherAddress => Jose::sign(
                $claims,
                $this->keys->privateKey(MessageType::IdToken),
                [
                    'kid' => $this->keys->kid(MessageType::IdToken),
                    'jku' => $configuration->url(MessageType::IdToken->jwksPath()),
                ],
            ),
            default => Jose::sign($claims, $this->keys->privateKey(MessageType::Statement), $header),
        };
    }

    private function envelope(
        MockConfiguration $configuration,
        ClientRegistration $client,
        string $verklaringId,
        string $statement,
        string $subject,
        Scenario $scenario,
        int $now,
    ): string {
        $claims = [
            'iss' => $configuration->envelopeIssuer,
            'aud' => $client->envelopeAudience,
            'iat' => $now,
            'exp' => $now + $configuration->envelopeSeconds,
            'loa_authn' => $configuration->loaAuthn,
            'verklaring_id' => $verklaringId,
            $configuration->statementClaim => $statement,
        ];

        switch ($scenario) {
            case Scenario::EnvelopeWrongIssuer:
                $claims['iss'] = 'wrong-' . $configuration->envelopeIssuer;
                break;
            case Scenario::EnvelopeWrongAudience:
                $claims['aud'] = 'another-audience';
                break;
            case Scenario::EnvelopeExpired:
                $claims['iat'] = $now - 900;
                $claims['exp'] = $now - 600;
                break;
            case Scenario::EnvelopeWrongLoa:
                $claims['loa_authn'] = self::WRONG_LOA;
                break;
            case Scenario::EnvelopeWithoutVerklaringId:
                unset($claims['verklaring_id']);
                break;
            case Scenario::EnvelopeWithSub:
                $claims['sub'] = $subject;
                break;
            case Scenario::EnvelopeSubMismatch:
                $claims['sub'] = Jose::base64Url(hash('sha256', 'another-subject|' . $subject, true));
                break;
            default:
                break;
        }

        $header = ['kid' => $this->keys->kid(MessageType::Envelope)];

        return match ($scenario) {
            Scenario::EnvelopeBadSignature => Jose::sign($claims, $this->keys->roguePrivateKey(), $header),
            Scenario::EnvelopeUnknownKid => Jose::sign(
                $claims,
                $this->keys->roguePrivateKey(),
                ['kid' => KeyRing::UNKNOWN_KID],
            ),
            Scenario::EnvelopeSignedWithIdTokenKey => Jose::sign(
                $claims,
                $this->keys->privateKey(MessageType::IdToken),
                ['kid' => $this->keys->kid(MessageType::IdToken)],
            ),
            Scenario::EnvelopeJkuOtherAddress => Jose::sign(
                $claims,
                $this->keys->privateKey(MessageType::IdToken),
                [
                    'kid' => $this->keys->kid(MessageType::IdToken),
                    'jku' => $configuration->url(MessageType::IdToken->jwksPath()),
                ],
            ),
            default => Jose::sign($claims, $this->keys->privateKey(MessageType::Envelope), $header),
        };
    }
}
