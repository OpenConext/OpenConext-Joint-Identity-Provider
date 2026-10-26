<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Http;

use RuntimeException;

/**
 * The provider gave no usable answer: a timeout, an unreachable address, a redirect, a 5xx answer or a
 * body over the size limit (design §13). The message never holds a received value.
 */
final class NoAnswer extends RuntimeException
{
}
