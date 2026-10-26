<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\EngineBlock;

use SensitiveParameter;
use Symfony\Component\HttpFoundation\Request;

/**
 * EngineBlock's server-to-server calls carry the API token as is in `Authorization`, without a scheme
 * (design §12). The `Authentication` header holds the same secret but is never read.
 */
final class ApiTokenAuthenticator
{
    public static function isAuthorized(Request $request, #[SensitiveParameter] string $apiToken): bool
    {
        $values = $request->headers->all('authorization');

        return count($values) === 1 && is_string($values[0]) && hash_equals($apiToken, $values[0]);
    }
}
