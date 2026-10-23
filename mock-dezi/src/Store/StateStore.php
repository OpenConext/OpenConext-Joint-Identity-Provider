<?php

declare(strict_types=1);

namespace MockDezi\Store;

use MockDezi\Configuration\Paths;
use MockDezi\Scenario\EndpointMode;
use MockDezi\Scenario\Scenario;
use MockDezi\Scenario\StatementBehaviour;
use MockDezi\Store\Record\AccessToken;
use MockDezi\Store\Record\AuthorizationCode;
use MockDezi\Store\Record\AuthorizationRequest;
use MockDezi\Store\Record\LoginSession;
use Psr\Clock\ClockInterface;
use RuntimeException;

/**
 * The mock's state in one file. Every read-modify-write runs under an exclusive lock, so a code, an access token
 * or a client assertion jti is consumed exactly once, also under concurrent requests (single node).
 */
final readonly class StateStore
{
    private const array ALLOWED_CLASSES = [
        State::class,
        AuthorizationRequest::class,
        AuthorizationCode::class,
        AccessToken::class,
        LoginSession::class,
        Scenario::class,
        StatementBehaviour::class,
        EndpointMode::class,
    ];

    public function __construct(
        private string $projectDir,
        private string $stateFile,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @template T
     * @param callable(State): T $operation
     * @return T
     */
    public function transaction(callable $operation, bool $reset = false): mixed
    {
        $path = Paths::resolve($this->projectDir, $this->stateFile);
        $directory = dirname($path);
        if (!is_dir($directory) && !@mkdir($directory, 0o750, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Cannot create the state directory %s', $directory));
        }
        $handle = @fopen($path . '.lock', 'c');
        if ($handle === false) {
            throw new RuntimeException(sprintf('Cannot open the state file %s', $path));
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot lock the state file');
            }
            $contents = is_file($path) ? @file_get_contents($path) : '';
            if ($contents === false) {
                throw new RuntimeException('Cannot read the state file');
            }
            if (!$reset && $contents === '' && is_file($path)) {
                throw new RuntimeException('The state file is empty');
            }
            $state = $reset ? new State() : self::decode($contents);
            $state->prune($this->clock->now()->getTimestamp());
            $result = $operation($state);
            $serialized = serialize($state);
            // Exclusive creation preserves the directory's default ACL for host/container access.
            $temporary = $directory . '/.mock-state-' . bin2hex(random_bytes(16));
            $output = @fopen($temporary, 'x+b');
            if ($output === false) {
                throw new RuntimeException('Cannot create a temporary state file');
            }
            try {
                if (fwrite($output, $serialized) !== strlen($serialized) || !fflush($output)) {
                    throw new RuntimeException('Cannot write or flush the state file');
                }
                if (!rename($temporary, $path)) {
                    throw new RuntimeException('Cannot replace the state file');
                }
            } finally {
                fclose($output);
                if (is_file($temporary)) {
                    unlink($temporary);
                }
            }

            return $result;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function reset(): void
    {
        $this->transaction(static function (State $state): void {
            $state->clear();
        }, reset: true);
    }

    private static function decode(string $contents): State
    {
        if ($contents === '') {
            return new State();
        }
        $state = @unserialize($contents, ['allowed_classes' => self::ALLOWED_CLASSES]);

        if (!$state instanceof State) {
            throw new RuntimeException('Cannot decode the state file; reset it explicitly before continuing');
        }

        return $state;
    }
}
