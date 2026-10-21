<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Http;

use JsonException;

final readonly class ProviderResponse
{
    public function __construct(
        public int $statusCode,
        public string $body,
    ) {
    }

    /**
     * The body as a JSON object, or null when it is not one.
     *
     * @return array<string, mixed>|null
     */
    public function jsonObject(): ?array
    {
        try {
            $data = json_decode($this->body, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($data) || !str_starts_with(ltrim($this->body), '{')) {
            return null;
        }

        $object = [];
        foreach ($data as $key => $value) {
            $object[(string) $key] = $value;
        }

        return $object;
    }
}
