#!/usr/bin/env php
<?php

// Manage and EngineBlock settings of the JointIdentityProvider (JIP) POC (design §8, §17).
//
//   php devenv/bin/manage.php apply   creates or updates the test SP in Manage and pushes to EngineBlock
//   php devenv/bin/manage.php audit   read-only operator checklist (§17) against Manage, the running EngineBlock,
//                                     JIP's mock configuration and the test SP's rules; exit 1 on any FAIL
//
// Uses Manage's internal API with devconf's default credentials (MANAGE_API_USER / MANAGE_API_PASSWORD).

declare(strict_types=1);

use JointIdentityProvider\Devenv\ManageHttpFailure;
use Symfony\Component\Yaml\Yaml;

use function JointIdentityProvider\Devenv\pushToEngineBlock;

$devenv = dirname(__DIR__);
$root = dirname($devenv);
require $root . '/jip/vendor/autoload.php';
require __DIR__ . '/_manage.php';

const MANAGE = 'https://manage.dev.openconext.local/manage/api/internal/';
const SP_FILE = '/manage/jip-test-sp.json';

$command = $argv[1] ?? '';
if (!in_array($command, ['apply', 'audit'], true)) {
    fwrite(STDERR, "usage: manage.php apply|audit\n");
    exit(2);
}

/**
 * @param array<mixed>|null $body
 * @return array<mixed>
 */
function manage(string $method, string $path, ?array $body = null): array
{
    global $devenv;
    $curl = curl_init(MANAGE . $path);
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CAINFO => $devenv . '/certs/openconext-dev-ca.crt',
        CURLOPT_USERPWD => (getenv('MANAGE_API_USER') ?: 'sysadmin') . ':' . (getenv('MANAGE_API_PASSWORD') ?: 'secret'),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_TIMEOUT => 30,
    ]);
    if ($body !== null) {
        $json = json_encode($body === [] ? new stdClass() : $body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $json);
    }
    $answer = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if (!is_string($answer) || $status < 200 || $status > 299) {
        throw new ManageHttpFailure(
            sprintf('Manage %s %s answered HTTP %d', $method, $path, $status),
            $status,
            is_string($answer) ? $answer : '',
        );
    }
    $data = $answer === '' ? [] : json_decode($answer, true, 512, JSON_THROW_ON_ERROR);

    return is_array($data) ? $data : [];
}

/**
 * @return array<mixed>|null the full entity
 */
function entity(string $type, string $entityId): ?array
{
    $found = manage('POST', 'search/' . $type, ['entityid' => $entityId]);
    if (count($found) > 1) {
        throw new RuntimeException(sprintf('Manage holds %d %s entities for %s', count($found), $type, $entityId));
    }
    $id = $found[0]['_id'] ?? null;

    return is_string($id) ? manage('GET', sprintf('metadata/%s/%s', $type, $id)) : null;
}

/**
 * A parameter of the running EngineBlock, read as the web-server user so no cache file changes owner.
 */
function engineParameter(string $name): mixed
{
    $container = getenv('JIP_ENGINE_CONTAINER') ?: 'core-engine-1';
    $output = shell_exec(sprintf(
        'docker exec -u www-data -w /var/www/html %s php bin/console debug:container --parameter=%s --format=json 2>/dev/null',
        escapeshellarg($container),
        escapeshellarg($name),
    ));
    $data = is_string($output) ? json_decode($output, true) : null;
    if (!is_array($data) || !array_key_exists($name, $data)) {
        throw new RuntimeException(sprintf('EngineBlock parameter %s could not be read', $name));
    }

    return $data[$name];
}

/**
 * The organisations EngineBlock itself offers the service, from its IdP list for that SP.
 *
 * @return list<string>
 */
function engineConnections(string $spId): array
{
    global $devenv;
    $curl = curl_init('https://engine.dev.openconext.local/authentication/proxy/idps-metadata?sp-entity-id='
        . rawurlencode($spId));
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CAINFO => $devenv . '/certs/openconext-dev-ca.crt',
        CURLOPT_TIMEOUT => 30,
    ]);
    $xml = curl_exec($curl);
    if (!is_string($xml) || curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) {
        throw new RuntimeException('EngineBlock\'s IdP list for the service could not be read');
    }
    preg_match_all('/<md:EntityDescriptor[^>]*\sentityID="([^"]+)"/', $xml, $matches);
    $ids = $matches[1];
    sort($ids);

    return $ids;
}

if ($command === 'apply') {
    $wanted = json_decode((string) file_get_contents($devenv . SP_FILE), true, 512, JSON_THROW_ON_ERROR);
    $current = entity('saml20_sp', $wanted['data']['entityid']);
    if ($current === null) {
        manage('POST', 'metadata', $wanted);
        echo "created {$wanted['data']['entityid']}\n";
    } else {
        $wanted['data']['eid'] = $current['data']['eid'] ?? null;
        $compare = static fn (array $data): array => array_diff_key($data, ['revisionnote' => true, 'eid' => true]);
        if ($compare($current['data']) == $compare($wanted['data'])) {
            echo "unchanged {$wanted['data']['entityid']}\n";
        } else {
            manage('PUT', 'metadata', [
                'id' => $current['id'],
                'version' => $current['version'],
                'type' => 'saml20_sp',
                'data' => array_filter($wanted['data'], static fn (mixed $v): bool => $v !== null),
            ]);
            echo "updated {$wanted['data']['entityid']}\n";
        }
    }
    try {
        $completePush = pushToEngineBlock(static fn (): array => manage('GET', 'push'));
    } catch (RuntimeException $exception) {
        fwrite(STDERR, "push failed ({$exception->getMessage()})\n");
        exit(1);
    }
    echo $completePush ? "pushed\n" : "pushed to EngineBlock; the OIDC backend is unavailable\n";
    $connections = engineConnections($wanted['data']['entityid']);
    $expected = array_map(static fn (array $e): string => $e['name'], $wanted['data']['allowedEntities']);
    sort($expected);
    if ($connections !== $expected) {
        fwrite(STDERR, 'EngineBlock offers ' . implode(', ', $connections) . "; expected the pushed connections\n");
        exit(1);
    }
    echo 'EngineBlock offers the service: ' . implode(', ', $connections) . "\n";
    exit(0);
}

// audit
$fails = 0;
$ok = static function (string $message): void {
    printf("  \e[32mOK\e[0m      %s\n", $message);
};
$bad = static function (string $message) use (&$fails): void {
    printf("  \e[31mFAIL\e[0m    %s\n", $message);
    $fails++;
};
$check = static fn (bool $passed, string $message) => $passed ? $ok($message) : $bad($message);

$jip = Yaml::parseFile($root . '/jip/config/jip/mock.yaml');
$testSp = require $root . '/test-sp/config/test-sp.php';
$spId = $testSp['sp_entity_id'];
$service = $jip['services'][$spId] ?? null;
$prefix = $jip['attributes']['reserved_prefix'];
$binding = $jip['binding']['organisation_attribute'];
$flag = $jip['attributes']['login_flag'];
if (!is_array($service)) {
    $bad("JIP has no service {$spId}");
    exit(1);
}

$sp = entity('saml20_sp', $spId);
if ($sp === null) {
    $bad("Manage has no SP {$spId}: run devenv/bin/manage.php apply");
    exit(1);
}
$data = $sp['data'];
$fields = $data['metaDataFields'] ?? [];
$arp = $data['arp'] ?? [];
$arpAttributes = is_array($arp['attributes'] ?? null) ? $arp['attributes'] : [];

echo "\nDirect route and switch (§8, §17 checks 15, 16)\n";
$check(($fields['coin:collab_enabled'] ?? false) === true, 'coin:collab_enabled is on for the test SP');
$check(($fields['coin:trusted_proxy'] ?? false) !== true, 'the test SP is not a trusted proxy: direct route');
$manageOrganisations = array_map(static fn (array $e): string => $e['name'], $data['allowedEntities'] ?? []);
sort($manageOrganisations);
$jipOrganisations = $service['allowed_organisations'];
sort($jipOrganisations);
$check(
    ($data['allowedall'] ?? true) === false && $manageOrganisations === $jipOrganisations,
    sprintf('Manage connections equal JIP\'s approved list (version %s): %s', $service['connection_policy_version'], implode(', ', $jipOrganisations)),
);
$check(engineConnections($spId) === $jipOrganisations, 'EngineBlock\'s pushed connections for the service equal JIP\'s list');

echo "\nRelease policy and reserved namespace (§6, §17 checks 1, 2, 4, 17)\n";
$check(($arp['enabled'] ?? false) === true, 'explicit release policy (ARP enabled)');
$reserved = array_filter(array_keys($arpAttributes), static fn (string $n): bool => str_starts_with($n, $prefix));
$check($reserved === [], "ARP lists no name under {$prefix}");
$check(!array_key_exists($binding, $arpAttributes), 'ARP does not release the binding attribute');
$sources = [];
$renames = [];
foreach ($arpAttributes as $name => $rules) {
    foreach ($rules as $rule) {
        $sources[] = $rule['source'] ?? 'idp';
        if (isset($rule['release_as']) && $rule['release_as'] !== '' || ($rule['use_as_nameid'] ?? false) === true) {
            $renames[] = $name;
        }
    }
}
$check($renames === [], 'no release_as or use_as_nameid rule in the ARP');
$check(array_values(array_unique($sources)) === ['idp'] || $sources === [], 'every ARP source is idp: no attribute aggregation');
$check(($fields['coin:attribute_aggregation_required'] ?? false) !== true, 'no attribute aggregation required');
$check(trim((string) ($data['manipulation'] ?? '')) === '', 'no SP attribute manipulation');

echo "\nStepup triggers (§9 item 10, §17 check 7)\n";
$check(!isset($fields['coin:stepup:requireloa']), 'no Stepup level on the service (coin:stepup:requireloa)');
$check(($fields['coin:policy_enforcement_decision_required'] ?? false) !== true, 'no policy enforcement on the service');
$policies = manage('POST', 'search/policy', []);
$check($policies === [], sprintf('no policy in Manage (%d found)', count($policies)));
require $root . '/test-sp/vendor/autoload.php';
putenv('TEST_SP_IDP_CERTIFICATE_FILE=' . $devenv . '/upstream/OpenConext-devconf/core/engine/engineblock.crt');
$authnRequest = (new OneLogin\Saml2\AuthnRequest(new OneLogin\Saml2\Settings(
    JointIdentityProvider\TestSp\Configuration::load($root . '/test-sp/config/test-sp.php')->saml,
)))->getXML();
$check(
    !str_contains($authnRequest, 'RequestedAuthnContext') && !str_contains($authnRequest, 'ForceAuthn="true"'),
    'the test SP\'s login request carries no RequestedAuthnContext',
);

foreach ($service['allowed_organisations'] as $organisation) {
    echo "\nOrganisation {$organisation} (§17 checks 4, 7, 17)\n";
    $idp = entity('saml20_idp', $organisation);
    if ($idp === null) {
        $bad('not in Manage');
        continue;
    }
    $check(trim((string) ($idp['data']['manipulation'] ?? '')) === '', 'no IdP attribute manipulation');
    $stepup = array_map(static fn (array $e): string => $e['name'], $idp['data']['stepupEntities'] ?? []);
    $check(!in_array($spId, $stepup, true), 'no Stepup setting of this organisation for the service');
}

echo "\nEngineBlock (running) and JIP (§12, §17 checks 3, 5, 8, 11, 20)\n";
$check(engineParameter('feature_enable_sram_interrupt') === true, 'feature_enable_sram_interrupt is on');
$check(engineParameter('sram.base_url') === 'https://jip.dev.openconext.local/', 'sram.base_url points at JIP');
$check(
    engineParameter('sram.authz_location') === 'authz' && engineParameter('sram.interrupt_location') === 'interrupt'
    && engineParameter('sram.attributes_location') === 'attributes',
    'sram.* locations are authz, interrupt and attributes',
);
$check(engineParameter('sram.verify_peer') === true, 'sram.verify_peer is on');
$timeout = engineParameter('http_client.timeout');
$check($timeout === $jip['engineblock']['call_timeout_seconds'], "http_client.timeout ({$timeout}) equals JIP's engineblock.call_timeout_seconds");
$manipulationsFirst = engineParameter('feature_run_all_manipulations_prior_to_consent');
$ok(sprintf('feature_run_all_manipulations_prior_to_consent is stated: %s', var_export($manipulationsFirst, true)));

$allowed = engineParameter('sram.allowed_attributes');
sort($allowed);
$released = [$flag];
foreach ($service['release'] as $claim) {
    $released[] = $jip['attributes']['claims'][$claim]['attribute'];
}
sort($released);
$rules = $testSp['access_rules'];
$required = [$rules['login_flag'], $rules['dezi_number'], $rules['subscriber'], $rules['role']];
sort($required);
$check($allowed === $released, 'sram.allowed_attributes equals JIP\'s release set plus the login flag');
$check($required === $released, 'the test SP\'s required set equals JIP\'s release set plus the login flag');
$check(
    array_filter($allowed, static fn (string $n): bool => !str_starts_with($n, $prefix)) === [],
    "every sram.allowed_attributes name lies under {$prefix}",
);
$check(is_string($service['restart_login_url'] ?? null), 'the service has a restart-login URL');

printf("\nManage audit: %d FAIL\n", $fails);
exit($fails === 0 ? 0 : 1);
