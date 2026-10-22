<?php

// The JIP POC test SP (design §7, §11). Local development only.
// The DEZI attribute names are govroam placeholders (design §6, §10) and match JIP's config/jip/mock.yaml and
// EngineBlock's sram.allowed_attributes (devenv/engine/zz_jip_sbs.yaml).

declare(strict_types=1);

return [
    'base_url' => 'https://jip-test-sp.dev.openconext.local/',
    'sp_entity_id' => 'https://jip-test-sp.dev.openconext.local/saml/metadata',
    'idp_entity_id' => 'https://engine.dev.openconext.local/authentication/idp/metadata',
    'idp_sso_url' => 'https://engine.dev.openconext.local/authentication/idp/single-sign-on',
    // EngineBlock's signing certificate (devconf core/engine/engineblock.crt), mounted read-only.
    'idp_certificate_file' => getenv('TEST_SP_IDP_CERTIFICATE_FILE') ?: '/etc/jip-test-sp/engineblock.crt',
    'access_rules' => [
        'reserved_prefix' => 'urn:mace:govroam.nl:attribute-def:dezi:',
        'login_flag' => 'urn:mace:govroam.nl:attribute-def:dezi:login',
        'dezi_number' => 'urn:mace:govroam.nl:attribute-def:dezi:dezi-nummer',
        'subscriber' => 'urn:mace:govroam.nl:attribute-def:dezi:abonnee-nummer',
        'role' => 'urn:mace:govroam.nl:attribute-def:dezi:rol-code',
        // Synthetic POC rules (mock DEZI fixtures); a real application owner sets its own (design §7, §10).
        'permitted_subscribers' => ['90000001'],
        'role_required' => true,
        'permitted_roles' => ['01.000'],
    ],
];
