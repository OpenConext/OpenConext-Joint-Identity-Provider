<?php

declare(strict_types=1);

namespace JointIdentityProvider\Devenv;

use RuntimeException;

final class ManageHttpFailure extends RuntimeException
{
    public function __construct(string $message, public readonly int $status, public readonly string $responseBody)
    {
        parent::__construct($message);
    }
}

/**
 * Returns false only for the known unavailable devconf OIDC backend.
 * Unknown HTTP errors, transport failures and malformed responses must still fail the command.
 *
 * @param callable(): mixed $push
 */
function pushToEngineBlock(callable $push): bool
{
    try {
        $push();

        return true;
    } catch (ManageHttpFailure $failure) {
        $data = json_decode($failure->responseBody, true);
        $knownMessage = 'Error in push to OIDC (https://connect.dev.openconext.local/manage/connections)'
            . ' status 503 SERVICE_UNAVAILABLE and response <html><body><h1>503 Service Unavailable</h1>'
            . "\nNo server is available to handle this request.\n</body></html>\n";
        if ($failure->status !== 500 || $data !== ['message' => $knownMessage]) {
            throw $failure;
        }

        return false;
    }
}
