<?php

declare(strict_types=1);

namespace MockDezi\Key;

use MockDezi\Scenario\Endpoint;

/**
 * The message types that DEZI signs, each with its own key and key address (design §14).
 * PROVISIONAL: the envelope's key address is a mock choice; DEZI's is open (design §10, §16).
 */
enum MessageType: string
{
    case IdToken = 'id_token';
    case Envelope = 'envelope';
    case Statement = 'statement';

    public function jwksPath(): string
    {
        return match ($this) {
            self::IdToken => '/openid/connect/jwks.json',
            self::Envelope => '/envelope/jwks.json',
            self::Statement => '/dezi/jwks.json',
        };
    }

    public function endpoint(): Endpoint
    {
        return match ($this) {
            self::IdToken => Endpoint::JwksIdToken,
            self::Envelope => Endpoint::JwksEnvelope,
            self::Statement => Endpoint::JwksStatement,
        };
    }

    /**
     * Where the `redirect` mode of this key set points: another message type's approved key address.
     */
    public function redirectTarget(): self
    {
        return $this === self::IdToken ? self::Statement : self::IdToken;
    }

    public function keyFile(): string
    {
        return str_replace('_', '-', $this->value) . '.pem';
    }
}
