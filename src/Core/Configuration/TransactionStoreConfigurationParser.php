<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Configuration\Reader\ConfigNode;

/**
 * Validates the transaction store's connection settings, DSN inputs and environment-specific TLS rules.
 */
final readonly class TransactionStoreConfigurationParser
{
    public function parse(ConfigNode $node, ?Environment $environment): ?TransactionStoreConfiguration
    {
        if (!$node->requireMap()) {
            return null;
        }
        $node->allowOnly('host', 'port', 'database', 'user', 'password', 'tls_ca');

        // Host and database name end up in the PDO DSN, so they may not carry DSN syntax.
        $hostNode = $node->get('host');
        $host = $hostNode->requireString();
        if (
            $host !== null
            && (str_contains($host, ':')
                ? filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false
                : preg_match('/^[A-Za-z0-9.-]+\z/', $host) !== 1)
        ) {
            $hostNode->error('must be a host name or IP address');
            $host = null;
        }

        if ($host !== null && strcasecmp($host, 'localhost') === 0) {
            $hostNode->error('use 127.0.0.1 for a local TCP connection instead of localhost');
            $host = null;
        }

        $portNode = $node->get('port');
        $port = $portNode->requirePositiveInt();
        if ($port !== null && $port > 65535) {
            $portNode->error('must be a port number up to 65535');
            $port = null;
        }

        $databaseNode = $node->get('database');
        $database = $databaseNode->requireString();
        if ($database !== null && preg_match('/^[A-Za-z0-9_]{1,64}\z/', $database) !== 1) {
            $databaseNode->error('must be at most 64 letters, digits or underscores');
            $database = null;
        }

        $user = $node->get('user')->requireString();
        $password = $node->get('password')->requireString();

        $tlsNode = $node->get('tls_ca');
        $tlsCa = $environment === Environment::Mock || $environment === null
            ? $tlsNode->optionalString()
            : $tlsNode->requireString();
        if ($tlsCa !== null && (!str_starts_with($tlsCa, '/') || !is_file($tlsCa) || !is_readable($tlsCa))) {
            $tlsNode->error('must be an absolute path to a readable CA certificate file');
            $tlsCa = null;
        }

        return $host === null || $port === null || $database === null || $user === null || $password === null
            ? null
            : new TransactionStoreConfiguration($host, $port, $database, $user, $password, $tlsCa);
    }
}
