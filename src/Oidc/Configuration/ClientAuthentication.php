<?php

declare(strict_types=1);

namespace JointIdentityProvider\Oidc\Configuration;

enum ClientAuthentication: string
{
    case PrivateKeyJwt = 'private_key_jwt';
    case None = 'none';
}
