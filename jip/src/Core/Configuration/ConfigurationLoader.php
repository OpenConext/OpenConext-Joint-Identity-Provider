<?php

declare(strict_types=1);

namespace JointIdentityProvider\Core\Configuration;

use JointIdentityProvider\Core\Configuration\Reader\ConfigNode;
use JointIdentityProvider\Core\Configuration\Reader\ConfigurationErrors;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Loads the configuration file named by JIP_CONFIG_FILE and runs every startup check (design §17).
 * Whole-value `%env(NAME)%` references are replaced first; then no value may still be a placeholder.
 */
final readonly class ConfigurationLoader
{
    private const string ENV_REFERENCE = '/^%env\(([A-Za-z_][A-Za-z0-9_]*)\)%$/';
    private const string PLACEHOLDER = '/<[^<>]*>/';

    public function __construct(
        private ConfigurationParser $parser,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
        #[Autowire('%env(default::JIP_CONFIG_FILE)%')] private ?string $configFile,
        #[Autowire('%env(default::CONNECTOR_ENVIRONMENT)%')] private ?string $deploymentEnvironment,
        private ?RequestStack $requestStack = null,
    ) {
    }

    /**
     * @throws InvalidConfiguration
     */
    public function load(): JipConfiguration
    {
        // Keep the approved snapshot on the main request, including for subrequests. A new request
        // always reloads it, even when the container is reused by a persistent worker.
        $request = $this->requestStack?->getMainRequest();
        $configuration = $request?->attributes->get(JipConfiguration::class);
        if ($configuration instanceof JipConfiguration) {
            return $configuration;
        }

        return $this->reload();
    }

    /**
     * Reads the current configuration again, also when the request already holds a snapshot, and makes
     * it the request's snapshot. Used where a decision must rest on the current approved policy.
     *
     * @throws InvalidConfiguration
     */
    public function reload(): JipConfiguration
    {
        $request = $this->requestStack?->getMainRequest();
        $errors = new ConfigurationErrors();

        $data = $this->readFile($errors);
        if ($data !== null) {
            $data = $this->resolveEnvReferences($data, '', $errors);
            $this->reportPlaceholders($data, '', $errors);
        }

        if (!$errors->isEmpty()) {
            throw new InvalidConfiguration($errors->all());
        }

        // The parser returns null exactly when it reported a problem.
        $configuration = $this->parser->parse(ConfigNode::root($data, $errors), $errors, $this->deploymentEnvironment);
        if ($configuration === null) {
            throw new InvalidConfiguration($errors->all());
        }

        $request?->attributes->set(JipConfiguration::class, $configuration);

        return $configuration;
    }

    private function readFile(ConfigurationErrors $errors): mixed
    {
        if ($this->configFile === null || trim($this->configFile) === '') {
            $errors->add('JIP_CONFIG_FILE', 'is not set by the deployment');

            return null;
        }

        $path = str_starts_with($this->configFile, '/')
            ? $this->configFile
            : $this->projectDir . '/' . $this->configFile;
        $contents = is_file($path) && is_readable($path) ? @file_get_contents($path) : false;
        if ($contents === false) {
            $errors->add('JIP_CONFIG_FILE', 'names a file that cannot be read');

            return null;
        }

        try {
            return Yaml::parse($contents);
        } catch (ParseException $exception) {
            // The parser's message can quote the offending line, which may hold a secret.
            $errors->add('JIP_CONFIG_FILE', sprintf('is not valid YAML (line %d)', $exception->getParsedLine()));

            return null;
        }
    }

    private function resolveEnvReferences(mixed $value, string $path, ConfigurationErrors $errors): mixed
    {
        if (is_array($value)) {
            foreach ($value as $key => $child) {
                $value[$key] = $this->resolveEnvReferences($child, ConfigNode::joinPath($path, $key), $errors);
            }

            return $value;
        }

        if (!is_string($value) || !str_contains($value, '%env(')) {
            return $value;
        }

        if (preg_match(self::ENV_REFERENCE, $value, $match) !== 1) {
            $errors->add($path, 'may use %env(NAME)% only as the whole value');

            return null;
        }

        $resolved = self::readEnv($match[1]);
        if ($resolved === null) {
            $errors->add($path, sprintf('refers to environment variable %s, which is not set', $match[1]));
        }

        return $resolved;
    }

    private function reportPlaceholders(mixed $value, string $path, ConfigurationErrors $errors): void
    {
        if (is_string($value) && preg_match(self::PLACEHOLDER, $value) === 1) {
            $errors->add($path, 'is an unreplaced placeholder');

            return;
        }

        if (!is_array($value)) {
            return;
        }

        foreach ($value as $key => $child) {
            $childPath = ConfigNode::joinPath($path, $key);
            if (is_string($key) && preg_match(self::PLACEHOLDER, $key) === 1) {
                $errors->add($childPath, 'has an unreplaced placeholder as its key');
            }
            $this->reportPlaceholders($child, $childPath, $errors);
        }
    }

    private static function readEnv(string $name): ?string
    {
        $value = $_SERVER[$name] ?? $_ENV[$name] ?? getenv($name);

        return is_string($value) ? $value : null;
    }
}
