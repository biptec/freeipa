#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import patch

from ipaserver.install import (
    bindinstance, dsinstance, hostidentity, httpinstance,
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
