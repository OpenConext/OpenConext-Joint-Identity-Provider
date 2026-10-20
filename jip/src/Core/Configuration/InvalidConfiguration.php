<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use RuntimeException;

final class InvalidConfiguration extends RuntimeException
{
    /**
     * @param list<string> $errors
     */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(sprintf(
            "The JIP configuration is invalid (%d problem%s):\n- %s",
            count($errors),
            count($errors) === 1 ? '' : 's',
            implode("\n- ", $errors),
        ));
    }
}
