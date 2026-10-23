#!/usr/bin/env python3
"""Scripted browser for the JointIdentityProvider (JIP) POC login flow (design §3, §7, §18).

Plays one browser through the complete local stack: test SP -> EngineBlock -> Mujina (organisation IdP)
-> EngineBlock -> JIP -> mock DEZI provider -> JIP -> EngineBlock (consent) -> test SP, and prints the
test SP's access decision. Local development only; it trusts only the devconf dev CA.

  devenv/bin/login-flow.py accounts                      persist the synthetic Mujina accounts
  devenv/bin/login-flow.py login jip-anna --person anna --expect dezi
  devenv/bin/login-flow.py login jip-nonumber --expect organisation

The trace prints scheme, host and path only: query strings, form values and cookies can carry live
authentication material (design §20) and are never printed.
"""

import argparse
import json
import pathlib
import re
import sys
import urllib.parse

import requests
from bs4 import BeautifulSoup

DEVENV = pathlib.Path(__file__).resolve().parent.parent
CA = str(DEVENV / 'certs' / 'openconext-dev-ca.crt')
ACCOUNTS = json.loads((DEVENV / 'mujina' / 'accounts.json').read_text())
SP = 'https://jip-test-sp.dev.openconext.local/'
MUJINA = 'https://mujina-idp.dev.openconext.local'
MOCK_DEZI = 'mock-dezi.dev.openconext.local'
JIP = 'jip.dev.openconext.local'
MAX_STEPS = 40


def mujina_fields(name):
    account = ACCOUNTS['accounts'][name]
    fields = [('username', name), ('password', 'secret'), ('persist-me', 'on'),
              ('urn:mace:dir:attribute-def:uid', name),
              ('urn:mace:dir:attribute-def:displayName', f'JIP POC {name}'),
              ('urn:mace:dir:attribute-def:mail', f'{name}@example.com')]
    for value in account['binding'] or []:
        fields.append((ACCOUNTS['binding_attribute'], value))
    for attribute, values in account.get('extra', {}).items():
        fields.extend((attribute, value) for value in values)
    return fields


def safe(url):
    parts = urllib.parse.urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}{parts.path}'


class Browser:
    def __init__(self, verbose):
        self.session = requests.Session()
        self.session.verify = CA
        self.verbose = verbose
        self.trace = []

    def request(self, method, url, data=None):
        response = self.session.request(method, url, data=data, allow_redirects=False, timeout=30)
        self.trace.append(f'{method} {safe(url)} -> {response.status_code}')
        if self.verbose:
            print('  ' + self.trace[-1])
        return response

    def form(self, response, form):
        action = urllib.parse.urljoin(response.url, form.get('action') or response.url)
        fields = []
        for element in form.find_all(['input', 'button', 'select', 'textarea']):
            name = element.get('name')
            if not name or element.get('type') in ('submit', 'button', 'checkbox', 'radio') or element.name == 'button':
                continue
            fields.append((name, element.get('value', '')))
        return action, fields


def login(args):
    browser = Browser(args.verbose)
    response = browser.request('GET', SP + 'login')
    for _ in range(MAX_STEPS):
        if response.status_code in (301, 302, 303, 307, 308):
            target = urllib.parse.urljoin(response.url, response.headers['Location'])
            method = response.request.method if response.status_code in (307, 308) else 'GET'
            body = response.request.body if response.status_code in (307, 308) else None
            response = browser.request(method, target, body)
            continue

        host = urllib.parse.urlsplit(response.url).netloc
        page = BeautifulSoup(response.text, 'html.parser')
        forms = page.find_all('form')

        if host == urllib.parse.urlsplit(SP).netloc and urllib.parse.urlsplit(response.url).path == '/':
            return finish(args, browser, response, page, 'sp')
        if host == JIP and response.status_code >= 400 or host == JIP and not forms:
            return finish(args, browser, response, page, 'jip')
        if host == urllib.parse.urlsplit(MUJINA).netloc and urllib.parse.urlsplit(response.url).path == '/login':
            response = browser.request('POST', MUJINA + '/login', mujina_fields(args.account))
            continue
        if host == MOCK_DEZI and any(f.get('action', '').endswith('/authorize/login') for f in forms):
            form = next(f for f in forms if f.get('action', '').endswith('/authorize/login'))
            action, fields = browser.form(response, form)
            fields = [(n, v) for n, v in fields if n not in ('person', 'scenario', 'action')]
            fields += [('person', args.person), ('scenario', args.scenario), ('action', args.dezi_action)]
            response = browser.request('POST', action, fields)
            continue
        if host == MOCK_DEZI and any(f.get('action', '').endswith('/authorize/profile') for f in forms):
            form = next(f for f in forms if f.get('action', '').endswith('/authorize/profile'))
            action, fields = browser.form(response, form)
            fields = [(n, v) for n, v in fields if n not in ('profile', 'action')]
            choices = [i.get('value') for i in form.find_all('input', {'name': 'profile'})]
            fields += [('profile', args.profile or choices[0]), ('action', 'continue')]
            response = browser.request('POST', action, fields)
            continue
        saml_form = next((f for f in forms if f.find('input', {'name': re.compile('^SAML(Response|Request)$')})), None)
        if saml_form is not None:
            action, fields = browser.form(response, saml_form)
            response = browser.request('POST', action, fields)
            continue
        consent = next((f for f in forms if 'consent' in (f.get('action') or '')), None)
        if consent is not None:
            action, fields = browser.form(response, consent)
            response = browser.request('POST', action, fields)
            continue
        return finish(args, browser, response, page, 'unexpected')
    return finish(args, browser, response, BeautifulSoup(response.text, 'html.parser'), 'too many steps')


def text(element):
    return re.sub(r'\s+', ' ', element.get_text(' ')).strip() if element else ''


def finish(args, browser, response, page, where):
    if where == 'sp':
        decision = page.find('p', class_=re.compile('^(dezi|organisation|refused)$'))
        outcome = decision.get('class')[0] if decision else 'unknown'
        print(f'{args.account}: test SP decision {outcome}: {text(decision)}')
        codes = [text(c) for c in page.find_all('code')]
        if codes:
            print(f'  SP request ID {codes[0]}')
        if args.show_attributes:
            for table in page.find_all('table'):
                for row in table.find_all('tr')[1:]:
                    print('  ' + ' = '.join(text(c) for c in row.find_all('td')))
    elif where == 'jip':
        reason = page.find(string=re.compile('Reason'))
        # JIP's page for an unknown nonce or state names no failure type, log ID or restart link.
        invalid_link = 'not valid' in text(page.find('h1'))
        failure = text(reason.find_next('code')) if reason else 'link_not_valid' if invalid_link else 'unknown'
        restart = page.find('a', string=re.compile('Restart login'))
        log_id = page.find(string=re.compile('Log ID'))
        outcome = f'jip-error:{failure}'
        print(f'{args.account}: JIP error page HTTP {response.status_code}, {failure},'
              f' log ID {text(log_id.find_next("code")) if log_id else "-"},'
              f' restart link {"yes" if restart else "no"}')
        if args.restart and args.restart != ('yes' if restart else 'no'):
            print(f'  EXPECTED restart link {args.restart}')
            return 1
    else:
        outcome = f'stopped:{where}'
        print(f'{args.account}: stopped ({where}) at {safe(response.url)} HTTP {response.status_code}')
        print('  ' + text(page.find('h1') or page.find('title'))[:200])
    if not args.verbose:
        print('  route: ' + ' | '.join(t.split(' ')[1].split('/')[2] for t in browser.trace))
    if args.expect and outcome != args.expect:
        print(f'  EXPECTED {args.expect}, got {outcome}')
        return 1
    return 0


def accounts(_):
    for name in ACCOUNTS['accounts']:
        session = requests.Session()
        session.verify = CA
        response = session.post(MUJINA + '/login', data=mujina_fields(name), allow_redirects=False, timeout=30)
        print(f'{name}: {"persisted" if response.status_code == 302 else f"HTTP {response.status_code}"}')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('accounts', help='persist the synthetic Mujina accounts').set_defaults(run=accounts)
    flow = sub.add_parser('login', help='run one login through the complete stack')
    flow.add_argument('account', choices=sorted(ACCOUNTS['accounts']))
    flow.add_argument('--person', default='anna', help='mock DEZI person (mock-dezi/fixtures/profiles.yaml)')
    flow.add_argument('--profile', help='mock DEZI profile id when the person has several')
    flow.add_argument('--scenario', default='', help='mock DEZI scenario (empty: the default)')
    flow.add_argument('--dezi-action', default='login', choices=['login', 'cancel'])
    flow.add_argument('--expect', help='dezi, organisation, refused or jip-error:<failure type>')
    flow.add_argument('--restart', choices=['yes', 'no'], help='with a JIP error page: whether it must offer a restart link')
    flow.add_argument('--show-attributes', action='store_true')
    flow.add_argument('-v', '--verbose', action='store_true')
    flow.set_defaults(run=login)
    args = parser.parse_args()
    return args.run(args)


if __name__ == '__main__':
    sys.exit(main())
