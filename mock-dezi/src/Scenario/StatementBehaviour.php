<?php

declare(strict_types=1);

namespace MockDezi\Scenario;

/**
 * How the status endpoint answers for one statement (design §15). Profiles set active, revoked or other_status in
 * the fixtures; the admin API and the status scenarios set any value per verklaring_id.
 */
enum StatementBehaviour: string
{
    case Active = 'active';
    case Revoked = 'revoked';
    case OtherStatus = 'other_status';
    case NotFound = 'not_found';
    case BadRequest = 'bad_request';
    case ServerError = 'server_error';
    case Timeout = 'timeout';
    case Redirect = 'redirect';
    case InvalidBody = 'invalid_body';
    case WrongId = 'wrong_id';

    /**
     * @return list<string>
     */
    public static function registerValues(): array
    {
        return [self::Active->value, self::Revoked->value, self::OtherStatus->value];
    }

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }

    public function description(): string
    {
        return match ($this) {
            self::Active => '200 with the same ID and status actief',
            self::Revoked => '200 with the same ID and the revoked status',
            self::OtherStatus => '200 with the same ID and another status',
            self::NotFound => '404 application/problem+json, as acceptance answers an unknown statement',
            self::BadRequest => '400 application/problem+json (another 4xx)',
            self::ServerError => '500 (no answer)',
            self::Timeout => 'answers active only after timeout_delay_seconds (no answer in time)',
            self::Redirect => '302 to the same status URL with ?redirected=1, which answers active',
            self::InvalidBody => '200 with a body that is not JSON (no answer)',
            self::WrongId => '200 actief, but for another verklaring ID',
        };
    }
}
