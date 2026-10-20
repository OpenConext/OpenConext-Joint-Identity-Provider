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
    public function transaction(callable $operation): mixed
    {
        $path = Paths::resolve($this->projectDir, $this->stateFile);
        $directory = dirname($path);
        if (!is_dir($directory) && !@mkdir($directory, 0o750, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Cannot create the state directory %s', $directory));
        }
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            throw new RuntimeException(sprintf('Cannot open the state file %s', $path));
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot lock the state file');
            }
            $state = self::decode((string) stream_get_contents($handle));
            $state->prune($this->clock->now()->getTimestamp());
            $result = $operation($state);
            $serialized = serialize($state);
            if (!ftruncate($handle, 0) || !rewind($handle)) {
                throw new RuntimeException('Cannot truncate or rewind the state file');
            }
            if (fwrite($handle, $serialized) !== strlen($serialized) || !fflush($handle)) {
                throw new RuntimeException('Cannot write or flush the state file');
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
        });
    }

    private static function decode(string $contents): State
    {
        if ($contents === '') {
            return new State();
        }
        $state = @unserialize($contents, ['allowed_classes' => self::ALLOWED_CLASSES]);

        // A state file from an older version of the mock starts over.
        return $state instanceof State ? $state : new State();
    }
}
