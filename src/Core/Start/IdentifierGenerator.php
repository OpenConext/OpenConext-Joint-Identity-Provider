<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Start;

/**
 * Random identifiers for a new transaction (design §13).
 */
interface IdentifierGenerator
{
    /**
     * The transaction ID and SBS nonce: 256 random bits, base64url without padding.
     */
    public function transactionId(): string;

    /**
     * The separate log ID: 64 random bits as 16 lowercase hex characters. Never a credential.
     */
    public function logId(): string;
}
