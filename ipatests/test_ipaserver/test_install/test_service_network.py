#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import MagicMock, call, patch

from ipalib import errors
from ipapython.dn import DN

from ipaserver import dns_data_management
from ipaserver.install import (
    adtrustinstance, bindinstance, cainstance, dsinstance, hostidentity,
    httpinstance, installutils, service,
)
from ipaserver.install.server import replicainstall, upgrade as server_upgrade


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


def test_record_in_hosts_scans_all_alias_lines(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text(
        '10.0.0.10 other.example.test other\n'
        '10.0.0.10 ipa.example.test ipa\n'
    )

    record = installutils.record_in_hosts(
        '10.0.0.10', 'ipa.example.test', str(hosts))

    assert record == ('10.0.0.10', ['ipa.example.test', 'ipa'])


def test_add_record_to_hosts_is_idempotent(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text('10.0.0.10\tipa.example.test ipa\n')

    installutils.add_record_to_hosts(
        '10.0.0.10', 'ipa.example.test', str(hosts))
    installutils.add_record_to_hosts(
        '10.0.0.10', 'ipa.example.test', str(hosts))

    assert hosts.read_text().count('10.0.0.10\tipa.example.test ipa\n') == 1


def test_read_password_file_requires_owner_only_regular_file(tmp_path):
    password_file = tmp_path / 'password'
    password_file.write_text('Secret123\n')
    password_file.chmod(0o600)

    assert installutils.read_password_file(str(password_file)) == 'Secret123'

    password_file.chmod(0o640)
    with pytest.raises(ValueError, match='group or others'):
        installutils.read_password_file(str(password_file))


def test_read_password_file_requires_one_secret(tmp_path):
    password_file = tmp_path / 'password'
    password_file.write_text('first\nsecond\n')
    password_file.chmod(0o600)

    with pytest.raises(ValueError, match='exactly one secret'):
        installutils.read_password_file(str(password_file))


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


def test_find_forward_zone_supports_nested_service_hostname():
    api_mock = MagicMock()

    def zone_exists(zone, api=None):
        return zone == 'example.test.'

    with patch.object(bindinstance, 'dns_zone_exists', side_effect=zone_exists):
        zone, owner = bindinstance.find_forward_zone(
            'dns.svc.example.test', api=api_mock)

    assert zone == 'example.test.'
    assert owner == 'dns.svc'


def test_bind_split_endpoint_publishes_nested_dns_record():
    bind = object.__new__(bindinstance.BindInstance)
    bind.api = MagicMock()
    address = FakeAddress('10.0.1.53', 4)

    with patch.object(
            bindinstance, 'find_forward_zone',
            return_value=('example.test.', 'dns.svc')), \
            patch.object(bindinstance, 'add_fwd_rr') as add_fwd, \
            patch.object(bindinstance, 'find_reverse_zone', return_value=None):
        bind._BindInstance__add_master_records(
            'dns.svc.example.test', [address])

    add_fwd.assert_called_once_with(
        'example.test.', 'dns.svc', address, bind.api)


def test_ipa_ca_uses_local_directory_endpoint_addresses():
    records = object.__new__(dns_data_management.IPASystemRecords)
    records.domain_abs = bindinstance.DNSName('example.test.')
    records.api_instance = MagicMock()
    records.api_instance.env.host = 'ipa.svc.example.test'
    records.api_instance.env.ipa_ipv4_address = '10.0.0.10'
    records.api_instance.env.ipa_ipv6_address = '2001:db8:1::10'
    zone_obj = dns_data_management.zone.Zone(
        records.domain_abs, relativize=False)

    with patch.object(
            dns_data_management.installutils,
            'resolve_rrsets_nss') as resolve:
        records._IPASystemRecords__add_ca_records_from_hostname(
            zone_obj, bindinstance.DNSName('ipa.svc.example.test.'))

    text = zone_obj.to_text()
    assert 'ipa-ca.example.test. 3600 IN A 10.0.0.10' in text
    assert 'ipa-ca.example.test. 3600 IN AAAA 2001:db8:1::10' in text
    resolve.assert_not_called()


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
    assert 'verify_unique_host 10.0.0.10 ipa.example.test' in helper_text
    assert 'verify_unique_host 2001:db8:1::10 ipa.example.test' in helper_text
    assert 'verify_unique_host 10.0.1.53 dns.example.test' in helper_text
    assert ('count=$(getent ahosts "$hostname" | awk -v address="$address" '
            "        '$1 == address && $2 == \"STREAM\" { count += 1 } "
            "END { print count + 0 }')") in helper_text
    assert 'address="$address" \n' not in helper_text
    assert 'wait_address 10.0.0.10' in helper_text
    assert 'wait_address 2001:db8:1::10' in helper_text
    assert 'ReadWritePaths=/etc/hosts' in dropin_text
    assert 'TimeoutStartSec=180' in dropin_text
    assert 'ExecStartPre={0}'.format(helper) in dropin_text
    assert helper.stat().st_mode & 0o111
    tasks_mock.systemd_daemon_reload.assert_called_once_with()


def test_replica_schedules_clean_restart_after_post_import_setup():
    ds = object.__new__(dsinstance.DsInstance)
    ds.step = MagicMock()
    ds.start_creation = MagicMock()

    with patch.object(dsinstance.DsInstance, 'init_info'), \
            patch.object(
                dsinstance.DsInstance,
                '_DsInstance__common_setup'), \
            patch.object(
                dsinstance.DsInstance,
                '_DsInstance__common_post_setup'):
        ds.create_replica(
            'EXAMPLE.TEST', 'master.example.test', 'replica.example.test',
            'example.test', 'dm-password', DN(('o', 'EXAMPLE.TEST')),
            DN(('cn', 'Certificate Authority'), ('o', 'EXAMPLE.TEST')),
            MagicMock(),
        )

    labels = [call.args[0] for call in ds.step.call_args_list]
    assert labels[-1] == (
        'stabilizing directory server after initial replication')
    restart = ds.step.call_args_list[-1].args[1]
    assert restart.__func__ is dsinstance.DsInstance._DsInstance__restart_instance
    ds.start_creation.assert_called_once_with(runtime=30)


def test_split_upgrade_pins_local_ca_to_directory_identity():
    ca = MagicMock()
    ca.is_configured.return_value = True

    with patch.object(server_upgrade.cainstance, 'update_ipa_conf') as update:
        changed = server_upgrade._pin_split_local_ca_host_on_upgrade(
            True, 'ipa.example.test', 'master.example.test', ca)

    assert changed is True
    update.assert_called_once_with('ipa.example.test')


def test_split_upgrade_keeps_remote_ca_on_ca_less_replica():
    ca = MagicMock()
    ca.is_configured.return_value = False

    with patch.object(server_upgrade.cainstance, 'update_ipa_conf') as update:
        changed = server_upgrade._pin_split_local_ca_host_on_upgrade(
            True, 'ipa.example.test', 'master.example.test', ca)

    assert changed is False
    update.assert_not_called()


def test_split_upgrade_local_ca_pin_is_idempotent_and_split_only():
    ca = MagicMock()
    ca.is_configured.return_value = True

    with patch.object(server_upgrade.cainstance, 'update_ipa_conf') as update:
        already_local = server_upgrade._pin_split_local_ca_host_on_upgrade(
            True, 'ipa.example.test', 'ipa.example.test', ca)
        integrated = server_upgrade._pin_split_local_ca_host_on_upgrade(
            False, 'ipa.example.test', 'master.example.test', ca)

    assert already_local is False
    assert integrated is False
    update.assert_not_called()


def test_ca_replica_schedules_restart_after_ipaca_import():
    ca = object.__new__(cainstance.CAInstance)
    ca.realm = 'EXAMPLE.TEST'
    ca.external = 0
    ca.clone = False
    ca.step = MagicMock()
    ca.start_creation = MagicMock()
    ca.clean_pkispawn_files = MagicMock()

    with patch.object(cainstance, 'lookup_ldap_backend', return_value='bdb'), \
            patch.object(cainstance, 'minimum_acme_support', return_value=False), \
            patch.object(cainstance.os.path, 'exists', return_value=False):
        ca.configure_instance(
            'replica.example.test', 'dm-password', 'admin-password',
            pkcs12_info=('clone.p12', 'pin'),
            master_host='master.example.test',
            promote=True,
        )

    labels = [call.args[0] for call in ca.step.call_args_list]
    setup_index = labels.index('setting up initial replication')
    assert labels[setup_index + 1] == (
        'stabilizing CA directory server after initial replication')
    restart = ca.step.call_args_list[setup_index + 1].args[1]
    assert restart is installutils.restart_dirsrv
    assert labels[setup_index + 2] == (
        'revert time skew after initial replication')
    ca.start_creation.assert_called_once_with(runtime=180)


def test_late_split_service_creation_skips_missing_ipa_host():
    svc = object.__new__(service.Service)
    svc.fqdn = 'ipa.example.test'
    svc.realm = 'EXAMPLE.TEST'
    svc.service_prefix = 'cifs'
    svc.suffix = DN(('dc', 'example'), ('dc', 'test'))
    svc.api = MagicMock()
    svc.api.env.system_hostname = 'node.example.test'
    owner_dn = DN(
        ('fqdn', 'node.example.test'),
        ('cn', 'computers'), ('cn', 'accounts'), svc.suffix,
    )

    with patch.object(svc, '_managed_host_dn', return_value=owner_dn), \
            patch.object(svc, '_ensure_split_service_metadata') as metadata:
        svc._add_service_principal()

    svc.api.Command.service_add.assert_called_once_with(
        'cifs/ipa.example.test@EXAMPLE.TEST',
        force=True,
        skip_host_check=True,
    )
    metadata.assert_called_once_with(
        'cifs/node.example.test@EXAMPLE.TEST', owner_dn)


def test_split_service_keytab_retrieves_machine_alias_without_rekey():
    svc = object.__new__(service.Service)
    svc.fqdn = 'ipa.example.test'
    svc.realm = 'EXAMPLE.TEST'
    svc.service_prefix = 'cifs'
    svc.keytab = '/etc/samba/samba.keytab'
    svc.api = MagicMock()
    svc.api.env.ldap_uri = 'ldapi://example'

    with patch.object(svc, '_add_service_principal') as add, \
            patch.object(svc, 'clean_previous_keytab') as clean, \
            patch.object(svc, 'run_getkeytab') as getkeytab, \
            patch.object(svc, 'set_keytab_owner') as owner, \
            patch.object(
                svc, '_split_service_principal_alias',
                return_value='cifs/node.example.test@EXAMPLE.TEST'):
        svc.request_service_keytab()

    add.assert_called_once_with()
    clean.assert_called_once_with()
    assert getkeytab.call_args_list == [
        call(
            'ldapi://example', '/etc/samba/samba.keytab',
            'cifs/ipa.example.test@EXAMPLE.TEST'),
        call(
            'ldapi://example', '/etc/samba/samba.keytab',
            'cifs/node.example.test@EXAMPLE.TEST', retrieve=True),
    ]
    owner.assert_called_once_with()


def test_adtrust_split_cldap_uses_directory_hostname():
    adtrust = object.__new__(adtrustinstance.ADTRUSTInstance)
    adtrust.fqdn = 'ipa.example.test'
    entry = MagicMock()
    entry.single_value.get.return_value = None

    with patch.object(adtrustinstance, 'api') as api_mock:
        api_mock.env.ipa_ipv4_address = '10.0.0.10'
        api_mock.env.ipa_ipv6_address = '2001:db8:1::10'
        api_mock.Backend.ldap2.get_entry.return_value = entry
        adtrust.configure_cldap_listener()

    entry.__setitem__.assert_called_once_with(
        'nsslapd-listenhost', ['ipa.example.test'])
    api_mock.Backend.ldap2.update_entry.assert_called_once_with(entry)


def test_adtrust_normal_cldap_keeps_upstream_listener():
    adtrust = object.__new__(adtrustinstance.ADTRUSTInstance)
    adtrust.fqdn = 'ipa.example.test'

    with patch.object(adtrustinstance, 'api') as api_mock:
        api_mock.env.ipa_ipv4_address = None
        api_mock.env.ipa_ipv6_address = None
        adtrust.configure_cldap_listener()

    api_mock.Backend.ldap2.get_entry.assert_not_called()


def test_split_service_alias_is_deferred_during_replica_promotion():
    svc = object.__new__(service.Service)
    svc.promote = True
    svc.fqdn = 'ipa.example.test'
    svc.principal = 'ldap/ipa.example.test@EXAMPLE.TEST'
    svc.api = MagicMock()
    svc.api.env.system_hostname = 'node.example.test'

    assert svc._split_service_principal_alias() is None


def test_split_dns_name_requires_ipa_domain():
    zone, name = replicainstall._split_dns_name(
        'dc2.example.test', 'example.test')
    assert zone == 'example.test'
    assert name == 'dc2'


def test_split_dns_records_add_only_missing_addresses():
    remote_api = MagicMock()
    remote_api.Command.dnsrecord_show.return_value = {
        'result': {'arecord': ['10.0.0.11']}}
    addresses = [
        FakeAddress('10.0.0.11', 4),
        FakeAddress('2001:db8::11', 6),
    ]

    added = replicainstall._ensure_split_dns_records(
        remote_api, 'example.test', 'dc2.example.test', addresses)

    remote_api.Command.dnsrecord_add.assert_called_once_with(
        'example.test', 'dc2', aaaarecord='2001:db8::11')
    assert added == [
        ('example.test', 'dc2', 'aaaarecord', '2001:db8::11')]
