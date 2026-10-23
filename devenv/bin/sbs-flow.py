#!/usr/bin/env python3
"""EngineBlock-side transaction checks of the JointIdentityProvider (JIP) POC (design §12, §13, §15, §18).

Plays EngineBlock's server-to-server calls (POST /authz, POST /attributes) and a browser (GET /interrupt,
the mock DEZI provider's login page, GET /oidc/callback) against the running JIP and mock DEZI provider.
EngineBlock, Mujina and the test SP are not involved, so this covers the transaction scenarios that a
browser login through EngineBlock cannot produce: premature, repeated and concurrent result calls, two
tabs, callback replay, organisation refusal and withdrawal, revocation after login and renewal at delivery.

  devenv/bin/sbs-flow.py list
  devenv/bin/sbs-flow.py run [case ...]        every case when none is named

Local development only; it trusts only the devconf dev CA. The API token is read from devenv/.env and
never printed, nor are nonces, states, codes or cookies. `withdrawal` edits jip/config/jip/mock.yaml for
a few seconds and restores it. `renewal` waits about a minute. The mock DEZI provider's state is reset
before and after every case.
"""

import argparse
import concurrent.futures
import pathlib
import secrets
import sys
import time
import urllib.parse

import requests
from bs4 import BeautifulSoup

DEVENV = pathlib.Path(__file__).resolve().parent.parent
CA = str(DEVENV / 'certs' / 'openconext-dev-ca.crt')
JIP_CONFIG = DEVENV.parent / 'jip' / 'config' / 'jip' / 'mock.yaml'
JIP = 'https://jip.dev.openconext.local'
MOCK = 'https://mock-dezi.dev.openconext.local'
# The values below mirror jip/config/jip/mock.yaml and mock-dezi/fixtures/profiles.yaml.
SERVICE = 'https://jip-test-sp.dev.openconext.local/saml/metadata'
ORGANISATION = 'http://mock-idp'
OTHER_ORGANISATION = 'http://mock-idp2'
ALLOWED = "allowed_organisations: ['http://mock-idp']"
RETURN_URL = 'https://engine.dev.openconext.local/authentication/idp/process-sraminterrupt'
BINDING = 'urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer'
FLAG = 'urn:mace:govroam.nl:attribute-def:dezi:login'
NUMBER = 'urn:mace:govroam.nl:attribute-def:dezi:dezi-nummer'
PEOPLE = {
    'anna': ('900000001', 'd3e2a1c0-0001-4000-8000-000000000001'),
    'carla': ('900000003', 'd3e2a1c0-0003-4000-8000-000000000001'),
    'dirk': ('900000004', 'd3e2a1c0-0004-4000-8000-000000000001'),
}
ENGINEBLOCK_TIMEOUT = 10  # EngineBlock's http_client.timeout (devenv/engine/zz_jip_sbs.yaml)
RENEWAL_WAIT = 57  # revocation.decision_validity_seconds (60) less revocation.timeout_seconds (5), plus margin


def api_token():
    for line in (DEVENV / '.env').read_text().splitlines():
        if line.startswith('JIP_SBS_API_TOKEN='):
            return line.split('=', 1)[1].strip().strip('\'"')
    sys.exit('JIP_SBS_API_TOKEN is missing from devenv/.env: run devenv/bin/setup.sh')


def session():
    http = requests.Session()
    http.verify = CA
    return http


def mock_admin(method, path, body=None):
    response = session().request(method, MOCK + path, json=body if body is not None else {}, timeout=30)
    response.raise_for_status()


class Start:
    def __init__(self, response, continue_url):
        self.status = response.status_code
        self.body = response.json()
        self.nonce = self.body.get('nonce') or ''
        self.continue_url = continue_url


class EngineBlock:
    """EngineBlock's two server-to-server calls, with both token headers as EngineBlock sends them (§12)."""

    def __init__(self):
        self.http = session()
        token = api_token()
        self.headers = {'Authorization': token, 'Authentication': token, 'Accept': 'application/json'}

    def start(self, binding=None, organisation=ORGANISATION, extra=None, headers=None):
        continue_url = f'{RETURN_URL}?ID=_sbsflow{secrets.token_hex(8)}'
        attributes = {'urn:mace:dir:attribute-def:mail': ['sbs-flow@example.com']}
        if binding is not None:
            attributes[BINDING] = binding
        attributes.update(extra or {})
        body = {
            'user_id': 'urn:collab:person:example.com:sbs-flow',
            'eppn': 'sbs-flow@example.com',
            'external_subject_id': '',
            'email': ['sbs-flow@example.com'],
            'continue_url': continue_url,
            'service_id': SERVICE,
            'issuer_id': organisation,
            'attributes': attributes,
        }
        response = self.http.post(JIP + '/authz', json=body, headers=headers or self.headers, timeout=ENGINEBLOCK_TIMEOUT)
        return Start(response, continue_url)

    def result(self, nonce, headers=None):
        started = time.monotonic()
        response = self.http.post(JIP + '/attributes', json={'nonce': nonce}, headers=headers or self.headers,
                                  timeout=ENGINEBLOCK_TIMEOUT)
        body = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else None
        return response.status_code, body, time.monotonic() - started


class Browser:
    def __init__(self):
        self.http = session()

    def get(self, url):
        return self.http.get(url, allow_redirects=False, timeout=30)

    def hand_off(self, nonce):
        return self.get(f'{JIP}/interrupt?nonce={urllib.parse.quote(nonce)}')

    def provider_login(self, authorize_url, person, profile=None, scenario=''):
        """Completes the mock DEZI login and returns JIP's callback URL without following it."""
        response = self.get(authorize_url)
        for _ in range(6):
            if response.status_code in (302, 303):
                location = urllib.parse.urljoin(response.url, response.headers['Location'])
                if urllib.parse.urlsplit(location).netloc != urllib.parse.urlsplit(MOCK).netloc:
                    return location
                response = self.get(location)
                continue
            page = BeautifulSoup(response.text, 'html.parser')
            login = page.find('form', action=lambda a: (a or '').endswith('/authorize/login'))
            choose = page.find('form', action=lambda a: (a or '').endswith('/authorize/profile'))
            form = login or choose
            if form is None:
                raise RuntimeError(f'unexpected mock DEZI page, HTTP {response.status_code}')
            fields = {i.get('name'): i.get('value', '') for i in form.find_all('input', type='hidden') if i.get('name')}
            if login is not None:
                fields.update(person=person, scenario=scenario, action='login')
            else:
                choices = [i.get('value') for i in form.find_all('input', {'name': 'profile'})]
                fields.update(profile=profile or choices[0], action='continue')
            response = self.http.post(urllib.parse.urljoin(response.url, form['action']), data=fields,
                                      allow_redirects=False, timeout=30)
        raise RuntimeError('the mock DEZI login did not return to JIP')

    def jip_cookies(self):
        return sorted(c.name for c in self.http.cookies if c.name.startswith('jip_tx_'))


def page_outcome(response):
    page = BeautifulSoup(response.text, 'html.parser')
    reason = page.find(string=lambda s: s and 'Reason' in s)
    failure = reason.find_next('code').get_text() if reason else None
    restart = page.find('a', string='Restart login') is not None
    title = page.find('h1').get_text() if page.find('h1') else ''
    return failure, restart, title


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, condition, message):
        print(f'  {"PASS" if condition else "FAIL"}  {message}')
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        return condition


def complete(report, browser, start, person, profile=None):
    """Hand-off, mock DEZI login and callback for a pending transaction; returns the callback URL."""
    hand_off = browser.hand_off(start.nonce)
    location = hand_off.headers.get('Location', '')
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    report.check(
        hand_off.status_code == 302 and location.startswith(MOCK + '/authorize')
        and query.get('prompt') == ['login'] and query.get('max_age') == ['0']
        and query.get('code_challenge_method') == ['S256'] and 'state' in query and 'nonce' in query,
        'hand-off redirects to the mock DEZI provider with prompt=login, max_age=0, PKCE S256, state and nonce',
    )
    callback_url = browser.provider_login(location, person, profile)
    callback = browser.get(callback_url)
    report.check(
        callback.status_code == 302 and callback.headers.get('Location') == start.continue_url,
        f'callback for {person} succeeds and returns to EngineBlock with only the request ID',
    )
    return callback_url


def expect_start(report, start, message, label):
    report.check(
        start.status == 200 and start.body.get('msg') == 'interrupt' and len(start.nonce) >= 43
        and start.body.get('message') == message,
        f'{label}: interrupt with a non-empty nonce and message {message}',
    )


def expect_result(report, outcome, status, attributes, label):
    report.check(outcome[0] == status and (attributes is None or (outcome[1] or {}).get('attributes') == attributes),
                 f'{label}: HTTP {outcome[0]} (expected {status})')


def case_premature_repeat(report, eb):
    start = eb.start(['900000001'])
    expect_start(report, start, 'DEZI_LOGIN_REQUIRED', 'start for an account with a number')
    expect_result(report, eb.result(start.nonce), 403, None, 'result call before the hand-off')
    browser = Browser()
    hand_off = browser.hand_off(start.nonce)
    expect_result(report, eb.result(start.nonce), 403, None, 'result call while the user is at DEZI')
    callback_url = browser.provider_login(hand_off.headers['Location'], 'anna')
    browser.get(callback_url)
    outcome = eb.result(start.nonce)
    expect_result(report, outcome, 200, None, 'result call after the callback')
    attributes = (outcome[1] or {}).get('attributes', {})
    report.check(attributes.get(FLAG) == ['verified'] and attributes.get(NUMBER) == ['900000001'],
                 'the result holds the flag verified and the bound DEZI number')
    expect_result(report, eb.result(start.nonce), 404, None, 'repeated result call (a lost first answer is never re-delivered)')


def case_concurrent(report, eb):
    start = eb.start(['900000001'])
    complete(report, Browser(), start, 'anna')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = sorted(o[0] for o in pool.map(lambda _: eb.result(start.nonce), range(8)))
    report.check(statuses == [200] + [404] * 7, f'8 concurrent result calls: {statuses.count(200)} x 200, '
                 f'{statuses.count(404)} x 404 (expected exactly one 200)')


def case_two_tabs(report, eb):
    browser = Browser()
    first, second = eb.start(['900000001']), eb.start(['900000004'])
    first_hand_off, second_hand_off = browser.hand_off(first.nonce), browser.hand_off(second.nonce)
    report.check(len(browser.jip_cookies()) == 2, 'two hand-offs in one browser keep two transaction cookies')
    second_callback = browser.provider_login(second_hand_off.headers['Location'], 'dirk')
    first_callback = browser.provider_login(first_hand_off.headers['Location'], 'anna')
    second_answer, first_answer = browser.get(second_callback), browser.get(first_callback)
    report.check(second_answer.headers.get('Location') == second.continue_url
                 and first_answer.headers.get('Location') == first.continue_url,
                 'both tabs complete, in reverse order, each back to its own EngineBlock request')
    first_result, second_result = eb.result(first.nonce), eb.result(second.nonce)
    report.check((first_result[1] or {}).get('attributes', {}).get(NUMBER) == ['900000001']
                 and (second_result[1] or {}).get('attributes', {}).get(NUMBER) == ['900000004'],
                 'each tab delivers its own person\'s DEZI number')


def case_callback_replay(report, eb):
    start = eb.start(['900000001'])
    browser = Browser()
    hand_off = browser.hand_off(start.nonce)
    callback_url = browser.provider_login(hand_off.headers['Location'], 'anna')
    stolen = Browser().get(callback_url)
    failure, restart, _ = page_outcome(stolen)
    report.check(stolen.status_code == 400 and failure == 'callback_mismatch' and restart,
                 'callback in another browser (no transaction cookie): 400 callback_mismatch with restart link')
    own = browser.get(callback_url)
    report.check(own.status_code == 302 and own.headers.get('Location') == start.continue_url,
                 'the original browser still completes the unchanged transaction')
    replay = browser.get(callback_url)
    report.check(replay.status_code == 400 and page_outcome(replay)[0] == 'callback_mismatch',
                 'replayed callback after success: 400, the code is not redeemed again')
    expect_result(report, eb.result(start.nonce), 200, None, 'result after the replay')
    replay = browser.get(callback_url)
    report.check(replay.status_code == 400 and page_outcome(replay)[0] == 'already_used',
                 'replayed callback after delivery: 400 already_used')
    again = browser.hand_off(start.nonce)
    report.check(again.status_code == 400 and page_outcome(again)[0] == 'already_used',
                 'replayed hand-off after delivery: 400 already_used')


def case_skip(report, eb):
    for binding in (None, [], ['']):
        start = eb.start(binding)
        expect_start(report, start, 'DEZI_SKIPPED', f'binding {binding!r}')
        browser = Browser()
        hand_off = browser.hand_off(start.nonce)
        report.check(hand_off.status_code == 302 and hand_off.headers.get('Location') == start.continue_url
                     and not browser.jip_cookies(), 'hand-off returns straight to EngineBlock, no DEZI and no cookie')
        expect_result(report, eb.result(start.nonce), 200, {FLAG: ['skipped']}, 'result holds only the flag skipped')
        expect_result(report, eb.result(start.nonce), 404, None, 'second result call')


def case_start_input(report, eb):
    cases = [
        (['   '], None, 'malformed_binding', 'a binding value of only spaces sent directly as JSON'),
        (['900000001', '900000002'], None, 'malformed_binding', 'two binding values'),
        (None, {FLAG: ['verified']}, 'reserved_attribute', 'a forged login flag on an account without a number'),
        (['900000001'], {NUMBER: ['900000001']}, 'reserved_attribute', 'a forged DEZI number next to a valid binding'),
    ]
    for binding, extra, failure, label in cases:
        start = eb.start(binding, extra=extra)
        report.check(start.status == 200 and start.body.get('msg') == 'interrupt' and start.nonce
                     and 'message' not in start.body, f'{label}: interrupt with a nonce for a failed transaction')
        expect_result(report, eb.result(start.nonce), 403, None, f'{label}: result call')
        page = Browser().hand_off(start.nonce)
        outcome = page_outcome(page)
        report.check(page.status_code == 403 and outcome[0] == failure and not outcome[1],
                     f'{label}: hand-off shows final {failure} without restart link')


def case_organisation(report, eb):
    for binding, label in ((['900000001'], 'with a number'), (None, 'without a number')):
        start = eb.start(binding, organisation=OTHER_ORGANISATION)
        report.check(start.status == 200 and start.nonce and 'message' not in start.body,
                     f'organisation not allowed, {label}: failed transaction, never skipped')
        expect_result(report, eb.result(start.nonce), 403, None, f'organisation not allowed, {label}: result call')
        outcome = page_outcome(Browser().hand_off(start.nonce))
        report.check(outcome[0] == 'organisation_refused' and not outcome[1],
                     f'organisation not allowed, {label}: final organisation_refused, no restart link')


def case_authentication(report, eb):
    token = eb.headers['Authorization']
    wrong = {'Authorization': 'wrong-' + secrets.token_hex(16), 'Authentication': token, 'Accept': 'application/json'}
    report.check(eb.start(['900000001'], headers=wrong).status == 401,
                 'start with a wrong Authorization and a correct Authentication: 401')
    only = {'Authorization': token, 'Accept': 'application/json'}
    start = eb.start(['900000001'], headers=only)
    report.check(start.status == 200 and start.nonce, 'start with Authorization only: accepted')
    report.check(eb.result(start.nonce, headers=wrong)[0] == 401, 'result call with a wrong Authorization: 401')


def case_withdrawal(report, eb):
    verified = eb.start(['900000001'])
    complete(report, Browser(), verified, 'anna')
    skipped = eb.start(None)
    Browser().hand_off(skipped.nonce)
    original = JIP_CONFIG.read_bytes()
    if original.decode().count(ALLOWED) != 1:
        report.check(False, f'{JIP_CONFIG.name} holds "{ALLOWED}" exactly once')
        return
    try:
        JIP_CONFIG.write_bytes(original.decode().replace(ALLOWED, 'allowed_organisations: []').encode())
        expect_result(report, eb.result(verified.nonce), 403, None, 'organisation withdrawn before delivery, verified')
        expect_result(report, eb.result(skipped.nonce), 403, None, 'organisation withdrawn before delivery, skipped')
    finally:
        JIP_CONFIG.write_bytes(original)
    report.check(JIP_CONFIG.read_bytes() == original, f'{JIP_CONFIG.name} restored byte for byte')
    expect_result(report, eb.result(verified.nonce), 403, None, 'after restoring the policy the transaction stays failed')
    expect_result(report, eb.result(skipped.nonce), 403, None, 'after restoring the policy the skip stays failed')


def case_fresh_decision(report, eb):
    start = eb.start(['900000001'])
    complete(report, Browser(), start, 'anna')
    mock_admin('PUT', '/mock/endpoints/status', {'mode': 'server_error'})
    expect_result(report, eb.result(start.nonce), 200, None,
                  'a decision still valid at delivery needs no status request (status endpoint answers 500)')


def case_renewal(report, eb):
    starts = {person: eb.start([PEOPLE[person][0]]) for person in ('anna', 'dirk', 'carla')}
    for person, start in starts.items():
        complete(report, Browser(), start, person)
    print(f'  ....  waiting {RENEWAL_WAIT} s until the revocation decisions need renewal')
    time.sleep(RENEWAL_WAIT)
    mock_admin('PUT', f'/mock/statements/{PEOPLE["dirk"][1]}', {'behaviour': 'revoked'})
    mock_admin('PUT', f'/mock/statements/{PEOPLE["carla"][1]}', {'behaviour': 'timeout'})
    expect_result(report, eb.result(starts['anna'].nonce), 200, None, 'aged decision, statement still active: renewed')
    expect_result(report, eb.result(starts['dirk'].nonce), 403, None, 'aged decision, statement revoked after login')
    status, _, elapsed = eb.result(starts['carla'].nonce)
    report.check(status == 403 and elapsed < ENGINEBLOCK_TIMEOUT,
                 f'aged decision, status check unanswered: HTTP {status} after {elapsed:.1f} s '
                 f'(within EngineBlock\'s {ENGINEBLOCK_TIMEOUT} s)')
    expect_result(report, eb.result(starts['carla'].nonce), 403, None, 'the unanswered renewal left the transaction failed')


CASES = {
    'premature-repeat': (case_premature_repeat, 'result calls before completion, after it, and repeated'),
    'concurrent': (case_concurrent, 'concurrent result calls consume once'),
    'two-tabs': (case_two_tabs, 'two transactions in one browser'),
    'callback-replay': (case_callback_replay, 'callback in another browser, replayed callback and hand-off'),
    'skip': (case_skip, 'absent, empty-list and empty-string binding are skipped and delivered once'),
    'start-input': (case_start_input, 'malformed binding and reserved names at the start call'),
    'organisation': (case_organisation, 'an organisation outside the approved list'),
    'authentication': (case_authentication, 'Authorization is the only API credential'),
    'withdrawal': (case_withdrawal, 'organisation withdrawn before delivery (edits mock.yaml briefly)'),
    'fresh-decision': (case_fresh_decision, 'no outgoing request while the revocation decision is valid'),
    'renewal': (case_renewal, 'renewal, revocation after login and an unanswered renewal (waits ~1 min)'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list')
    run = sub.add_parser('run')
    run.add_argument('cases', nargs='*', metavar='case')
    args = parser.parse_args()
    unknown = [name for name in getattr(args, 'cases', []) if name not in CASES]
    if unknown:
        parser.error(f'unknown case {", ".join(unknown)}; see the list command')
    if args.command == 'list':
        for name, (_, description) in CASES.items():
            print(f'{name:18} {description}')
        return 0

    report = Report()
    engineblock = EngineBlock()
    for name in args.cases or list(CASES):
        print(f'{name}: {CASES[name][1]}')
        mock_admin('POST', '/mock/reset')
        try:
            CASES[name][0](report, engineblock)
        except RuntimeError as error:
            report.check(False, f'{name} stopped: {error}')
        except (requests.RequestException, KeyError, ValueError) as error:
            # Request exceptions can quote URLs that carry a nonce, state or code.
            report.check(False, f'{name} stopped: {type(error).__name__}')
        finally:
            mock_admin('POST', '/mock/reset')
    print(f'\n{report.passed} passed, {report.failed} failed')
    return 0 if report.failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
