#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import MagicMock, patch

from ipalib import errors
from ipapython.dn import DN

from ipaserver.install import (
    bindinstance, dsinstance, hostidentity, httpinstance, service,
)


class FakeAddress:
    def __init__(self, value, version):
        self.value = value
        self.version = version

    def __str__(self):
        return self.value

    def __hash__(self):
        return hash((self.value, self.version))

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and (
            self.value, self.version) == (other.value, other.version)


def test_bind_split_endpoint_generates_explicit_listeners():
    bind = object.__new__(bindinstance.BindInstance)
    bind.fqdn = 'ipa.example.test'
    bind.dns_hostname = 'dns.example.test'
    bind.ip_addresses = [
        FakeAddress('10.0.0.10', 4),
        FakeAddress('2001:db8:1::10', 6),
    ]
    bind.dns_ip_addresses = [
        FakeAddress('10.0.1.53', 4),
        FakeAddress('2001:db8:2::53', 6),
    ]
    bind.dns_over_tls = False
    bind.dns_policy = None
    bind.dns_over_tls_key = None
    bind.dns_over_tls_cert = None

    with patch.object(bindinstance.paths, 'NAMED_CRYPTO_POLICY_FILE', None), \
            patch.object(bind, '_get_dnssec_validation', return_value='yes'):
        bind._setup_sub_dict()

    listeners = bind.sub_dict['NAMED_SERVICE_LISTEN_OPTIONS']
    assert '127.0.0.1' in listeners
    assert '::1' in listeners
    assert '10.0.1.53' in listeners
    assert '2001:db8:2::53' in listeners
    assert '10.0.0.10' not in listeners
    assert '2001:db8:1::10' not in listeners
    assert 'any' not in listeners


def test_httpd_split_endpoint_generates_directory_listeners():
    with patch.object(httpinstance, 'api') as api_mock:
        api_mock.env.ipa_ipv4_address = '10.0.0.10'
        api_mock.env.ipa_ipv6_address = '2001:db8:1::10'
        listeners = httpinstance.HTTPInstance._split_httpd_listen_directives()
    assert 'Listen 10.0.0.10:80' in listeners
    assert 'Listen [2001:db8:1::10]:80' in listeners
    assert 'Listen 10.0.0.10:443 https' in listeners
    assert 'Listen [2001:db8:1::10]:443 https' in listeners


def test_temporary_hosts_records_are_removed_exactly(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text(
        '127.0.0.1 localhost\n'
        '10.0.0.20 other.example.test other\n'
    )
    addresses = [FakeAddress('10.0.0.10', 4)]

    with patch.object(hostidentity.paths, 'HOSTS', str(hosts)):
        added = hostidentity._ensure_local_hosts_records(
            'ipa.example.test', addresses)
        assert '10.0.0.10\tipa.example.test ipa\n' in hosts.read_text()

        hostidentity._remove_local_hosts_records(added)

    assert hosts.read_text() == (
        '127.0.0.1 localhost\n'
        '10.0.0.20 other.example.test other\n'
    )


def test_ds_split_listener_restart_skips_localhost_port_probe():
    ds = object.__new__(dsinstance.DsInstance)
    ds.fqdn = 'ipa.example.test'

    with patch.object(dsinstance, 'api') as api_mock, \
            patch.object(dsinstance.DsInstance, 'restart') as restart:
        api_mock.env.ipa_ipv4_address = '10.0.0.10'
        api_mock.env.ipa_ipv6_address = '2001:db8:1::10'
        ldap = api_mock.Backend.ldap2
        ldap.isconnected.return_value = True
        entry = {}
        ldap.get_entry.return_value = entry

        ds.configure_split_hostname_listeners()

    assert entry['nsslapd-listenhost'] == ['ipa.example.test']
    assert entry['nsslapd-securelistenhost'] == ['ipa.example.test']
    restart.assert_called_once_with()
    ldap.disconnect.assert_not_called()
    ldap.connect.assert_not_called()


def test_httpd_split_endpoint_pins_ipa_service_server_name():
    with patch.object(httpinstance, 'api') as api_mock:
        api_mock.env.system_hostname = 'node.example.test'
        directive = (
            httpinstance.HTTPInstance._split_httpd_server_name_directive(
                'ipa.example.test'))
    assert directive == 'ServerName ipa.example.test'


def test_httpd_normal_mode_does_not_add_server_name():
    with patch.object(httpinstance, 'api') as api_mock:
        api_mock.env.system_hostname = None
        directive = (
            httpinstance.HTTPInstance._split_httpd_server_name_directive(
                'ipa.example.test'))
    assert directive == ''


def test_bind_split_endpoint_uses_dns_runtime_identity():
    bind = object.__new__(bindinstance.BindInstance)
    bind.fqdn = 'ipa.example.test'
    bind.dns_hostname = 'dns.example.test'
    bind.realm = 'EXAMPLE.TEST'
    bind.service_prefix = 'DNS'
    assert bind.principal == 'DNS/dns.example.test@EXAMPLE.TEST'


def test_bind_normal_mode_keeps_ipa_runtime_identity():
    bind = object.__new__(bindinstance.BindInstance)
    bind.fqdn = 'ipa.example.test'
    bind.dns_hostname = None
    bind.realm = 'EXAMPLE.TEST'
    bind.service_prefix = 'DNS'
    assert bind.principal == 'DNS/ipa.example.test@EXAMPLE.TEST'


def test_bind_split_endpoint_sets_dns_server_id():
    bind = object.__new__(bindinstance.BindInstance)
    bind.fqdn = 'ipa.example.test'
    bind.dns_hostname = 'dns.example.test'
    bind.ip_addresses = [
        FakeAddress('10.0.0.10', 4),
        FakeAddress('2001:db8:1::10', 6),
    ]
    bind.dns_ip_addresses = [
        FakeAddress('10.0.1.53', 4),
        FakeAddress('2001:db8:2::53', 6),
    ]
    bind.dns_over_tls = False
    bind.dns_policy = None
    bind.dns_over_tls_key = None
    bind.dns_over_tls_cert = None

    with patch.object(bindinstance.paths, 'NAMED_CRYPTO_POLICY_FILE', None), \
            patch.object(bind, '_get_dnssec_validation', return_value='yes'):
        bind._setup_sub_dict()

    assert bind.sub_dict['FQDN'] == 'ipa.example.test'
    assert bind.sub_dict['DNS_SERVER_ID'] == 'dns.example.test'


def test_local_dns_server_mapping_uses_persisted_dns_hostname():
    with patch.object(bindinstance, 'api') as api_mock:
        api_mock.env.host = 'ipa.example.test'
        api_mock.env.dns_hostname = 'dns.example.test'
        result = bindinstance.dns_server_id_for_ipa_server(
            api_mock, 'ipa.example.test')
    assert result == 'dns.example.test'


def test_service_owner_uses_finalized_machine_host_when_present():
    svc = object.__new__(service.Service)
    svc.fqdn = 'ipa.example.test'
    svc.suffix = DN(('dc', 'example'), ('dc', 'test'))
    svc.api = MagicMock()
    svc.api.env.system_hostname = 'node.example.test'
    svc.api.Backend.ldap2.get_entry.return_value = {}

    owner = svc._managed_host_dn()
    assert owner[0]['fqdn'] == 'node.example.test'


def test_service_owner_uses_ipa_host_before_finalization():
    svc = object.__new__(service.Service)
    svc.fqdn = 'ipa.example.test'
    svc.suffix = DN(('dc', 'example'), ('dc', 'test'))
    svc.api = MagicMock()
    svc.api.env.system_hostname = 'node.example.test'
    svc.api.Backend.ldap2.get_entry.side_effect = errors.NotFound(reason='missing')

    owner = svc._managed_host_dn()
    assert owner[0]['fqdn'] == 'ipa.example.test'


def test_ds_split_bootstrap_generates_prestart_helper(tmp_path):
    ds = object.__new__(dsinstance.DsInstance)
    ds.serverid = 'EXAMPLE-TEST'
    ds.fqdn = 'ipa.example.test'
    libexec = tmp_path / 'libexec'
    systemd = tmp_path / 'systemd'

    with patch.object(dsinstance, 'api') as api_mock, \
            patch.object(dsinstance, 'tasks') as tasks_mock, \
            patch.object(dsinstance.paths, 'LIBEXEC_IPA_DIR', str(libexec)), \
            patch.object(
                dsinstance.paths, 'ETC_SYSTEMD_SYSTEM_DIR', str(systemd)):
        api_mock.env.ipa_ipv4_address = '10.0.0.10'
        api_mock.env.ipa_ipv6_address = '2001:db8:1::10'
        api_mock.env.dns_hostname = 'dns.example.test'
        api_mock.env.dns_ipv4_address = '10.0.1.53'
        api_mock.env.dns_ipv6_address = '2001:db8:2::53'

        ds.configure_split_network_bootstrap()

    helper = libexec / 'ipa-split-network-ready-EXAMPLE-TEST'
    dropin = (
        systemd / 'dirsrv@EXAMPLE-TEST.service.d' /
        'ipa-split-network.conf')
    helper_text = helper.read_text()
    dropin_text = dropin.read_text()

    assert 'ensure_host 10.0.0.10 ipa.example.test ipa' in helper_text
    assert 'ensure_host 2001:db8:1::10 ipa.example.test ipa' in helper_text
    assert 'ensure_host 10.0.1.53 dns.example.test dns' in helper_text
    assert 'wait_address 10.0.0.10' in helper_text
    assert 'wait_address 2001:db8:1::10' in helper_text
    assert 'ReadWritePaths=/etc/hosts' in dropin_text
    assert 'TimeoutStartSec=180' in dropin_text
    assert 'ExecStartPre={0}'.format(helper) in dropin_text
    assert helper.stat().st_mode & 0o111
    tasks_mock.systemd_daemon_reload.assert_called_once_with()
