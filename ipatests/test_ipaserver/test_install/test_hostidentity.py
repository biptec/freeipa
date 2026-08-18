#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import MagicMock, call, patch

import pytest

from ipalib import errors
from ipapython.kerberos import Principal
from ipaserver.install import hostidentity


REALM = 'EXAMPLE.TEST'
IPA_HOST = 'ipa.example.test'
SYSTEM_HOST = 'node.example.test'


def _not_found():
    return errors.NotFound(reason='missing test entry')


def test_transition_host_entry_moves_and_preserves_aliases():
    entry = {
        'krbprincipalname': [f'host/{IPA_HOST}@{REALM}'],
        'managedby': ['old-dn'],
    }
    ldap = MagicMock()
    ldap.get_entry.side_effect = [entry, _not_found(), entry]
    api_instance = MagicMock()

    with patch.object(hostidentity, '_host_dn',
                      side_effect=['old-dn', 'new-dn']), \
            patch.object(hostidentity, '_replace_dn_references') as replace:
        result = hostidentity.transition_host_entry(
            ldap, IPA_HOST, SYSTEM_HOST, REALM, api_instance)

    assert result is entry
    assert entry['krbcanonicalname'] == [f'host/{SYSTEM_HOST}@{REALM}']
    assert f'host/{IPA_HOST}@{REALM}' in entry['krbprincipalname']
    assert f'host/{SYSTEM_HOST}@{REALM}' in entry['krbprincipalname']
    assert entry['cn'] == [SYSTEM_HOST]
    assert entry['serverhostname'] == ['node']
    ldap.move_entry.assert_called_once_with('old-dn', 'new-dn')
    replace.assert_called_once_with(
        ldap, api_instance.env.basedn, 'old-dn', 'new-dn')


def test_transition_host_entry_is_idempotent_on_target_dn():
    entry = {
        'krbprincipalname': [f'host/{SYSTEM_HOST}@{REALM}'],
        'krbcanonicalname': [f'host/{SYSTEM_HOST}@{REALM}'],
        'cn': [SYSTEM_HOST],
        'serverhostname': ['node'],
    }
    ldap = MagicMock()
    ldap.get_entry.side_effect = [_not_found(), entry, entry]
    api_instance = MagicMock()

    with patch.object(hostidentity, '_host_dn',
                      side_effect=['old-dn', 'new-dn']), \
            patch.object(hostidentity, '_replace_dn_references') as replace:
        hostidentity.transition_host_entry(
            ldap, IPA_HOST, SYSTEM_HOST, REALM, api_instance)

    assert f'host/{IPA_HOST}@{REALM}' in entry['krbprincipalname']
    assert entry['krbcanonicalname'] == [f'host/{SYSTEM_HOST}@{REALM}']
    ldap.move_entry.assert_not_called()
    replace.assert_not_called()


def test_finalize_machine_identity_success():
    api_instance = MagicMock()
    with patch.object(hostidentity, 'transition_host_entry') as transition, \
            patch.object(hostidentity, '_add_service_principal_aliases') as aliases, \
            patch.object(hostidentity, '_ensure_local_host_keytab') as keytab, \
            patch.object(hostidentity, '_set_sssd_hostname') as sssd, \
            patch.object(hostidentity, '_set_krb5_machine_mapping') as krbmap, \
            patch.object(hostidentity, '_persist_hostnames') as persist, \
            patch.object(hostidentity.tasks, 'set_hostname') as set_hostname, \
            patch.object(hostidentity, 'verify_machine_identity') as verify:
        hostidentity.finalize_machine_identity(
            IPA_HOST, SYSTEM_HOST, REALM,
            fstore=MagicMock(), api_instance=api_instance)

    transition.assert_called_once_with(
        api_instance.Backend.ldap2, IPA_HOST, SYSTEM_HOST,
        REALM, api_instance)
    aliases.assert_called_once()
    keytab.assert_called_once_with(SYSTEM_HOST, REALM, api_instance)
    sssd.assert_called_once_with(SYSTEM_HOST, expected_hostname=IPA_HOST)
    krbmap.assert_called_once_with(
        SYSTEM_HOST, REALM, api_instance.env.domain)
    persist.assert_called_once()
    set_hostname.assert_called_once_with(SYSTEM_HOST)
    verify.assert_called_once()


def test_finalize_machine_identity_rolls_back_on_failure():
    api_instance = MagicMock()
    failure = RuntimeError('configuration write failed')
    with patch.object(hostidentity, 'transition_host_entry') as transition, \
            patch.object(hostidentity, '_add_service_principal_aliases'), \
            patch.object(hostidentity, '_ensure_local_host_keytab'), \
            patch.object(hostidentity, '_set_sssd_hostname') as sssd, \
            patch.object(hostidentity, '_set_krb5_machine_mapping'), \
            patch.object(hostidentity, '_persist_hostnames',
                         side_effect=failure), \
            patch.object(hostidentity, '_restore_single_hostname_config') as restore, \
            patch.object(hostidentity.tasks, 'set_hostname') as set_hostname:
        with pytest.raises(RuntimeError, match='configuration write failed'):
            hostidentity.finalize_machine_identity(
                IPA_HOST, SYSTEM_HOST, REALM,
                fstore=MagicMock(), api_instance=api_instance)

    assert transition.call_args_list == [
        call(api_instance.Backend.ldap2, IPA_HOST, SYSTEM_HOST,
             REALM, api_instance),
        call(api_instance.Backend.ldap2, SYSTEM_HOST, IPA_HOST,
             REALM, api_instance),
    ]
    assert sssd.call_args_list == [
        call(SYSTEM_HOST, expected_hostname=IPA_HOST),
        call(IPA_HOST, expected_hostname=SYSTEM_HOST),
    ]
    restore.assert_not_called()
    set_hostname.assert_called_once_with(IPA_HOST)


def test_set_sssd_hostname_accepts_already_finalized_value():
    config = MagicMock()
    domain = MagicMock()
    domain.get_option.return_value = SYSTEM_HOST
    config.list_active_domains.return_value = ['example.test']
    config.get_domain.return_value = domain
    sssd_service = MagicMock()

    with patch.object(hostidentity.SSSDConfig, 'SSSDConfig',
                      return_value=config), \
            patch.object(hostidentity.services, 'service',
                         return_value=sssd_service):
        hostidentity._set_sssd_hostname(
            SYSTEM_HOST, expected_hostname=IPA_HOST)

    domain.set_option.assert_called_once_with('ipa_hostname', SYSTEM_HOST)
    config.save_domain.assert_called_once_with(domain)
    config.write.assert_called_once_with()
    sssd_service.restart.assert_called_once_with()


def test_replace_dn_references_handles_attribute_options():
    entry = {
        'managedby': ['old-dn'],
        'ipaallowedtoperform;read_keys': ['old-dn', 'other-dn'],
    }
    ldap = MagicMock()
    ldap.MATCH_ANY = '|'
    ldap.find_entries.return_value = ([entry], False)
    ldap.make_filter_from_attr.side_effect = lambda attr, value: (
        f'({attr}={value})')
    ldap.combine_filters.return_value = 'combined-filter'

    hostidentity._replace_dn_references(
        ldap, 'base-dn', 'old-dn', 'new-dn')

    assert entry['managedby'] == ['new-dn']
    assert entry['ipaallowedtoperform;read_keys'] == [
        'new-dn', 'other-dn']
    ldap.update_entry.assert_called_once_with(entry)


def test_replica_prepare_restores_host_key_after_generation_failure():
    remote_ldap = MagicMock()
    remote_ldap.get_entry.return_value = {'memberof': []}
    remote_api = MagicMock()
    fstore = MagicMock()
    fstore.has_file.return_value = False
    sstore = MagicMock()
    sstore.get_state.return_value = None

    failure = RuntimeError('key generation failed')
    with patch.object(hostidentity, '_host_dn', return_value='host-dn'), \
            patch.object(hostidentity, 'transition_host_entry') as transition, \
            patch.object(hostidentity, '_remove_local_host_keytab') as remove, \
            patch.object(hostidentity, '_generate_remote_host_keytab',
                         side_effect=[failure, None]) as generate, \
            patch.object(hostidentity, '_set_sssd_hostname'), \
            patch.object(hostidentity, '_restore_single_hostname_config'), \
            patch.object(hostidentity.tasks, 'set_hostname'):
        with pytest.raises(RuntimeError, match='key generation failed'):
            hostidentity.prepare_replica_identity(
                SYSTEM_HOST, IPA_HOST, REALM, 'master.example.test',
                remote_ldap, remote_api, fstore, sstore)

    assert transition.call_args_list == [
        call(remote_ldap, SYSTEM_HOST, IPA_HOST, REALM, remote_api),
        call(remote_ldap, IPA_HOST, SYSTEM_HOST, REALM, remote_api),
    ]
    remove.assert_called_once_with(SYSTEM_HOST, REALM)
    assert generate.call_args_list == [
        call('master.example.test', IPA_HOST, REALM),
        call('master.example.test', SYSTEM_HOST, REALM),
    ]


def test_validate_dual_stack_service_addresses_orders_families():
    ipv6 = MagicMock(version=6)
    ipv6.__str__.return_value = '2a07:e580:a10::10'
    ipv6.get_matching_interface.return_value = object()
    ipv4 = MagicMock(version=4)
    ipv4.__str__.return_value = '10.16.16.90'
    ipv4.get_matching_interface.return_value = object()

    result = hostidentity.validate_dual_stack_service_addresses(
        'Directory Controller', [ipv6, ipv4])

    assert result == (ipv4, ipv6)


def test_validate_dual_stack_service_addresses_rejects_missing_family():
    ipv4a = MagicMock(version=4)
    ipv4a.get_matching_interface.return_value = object()
    ipv4b = MagicMock(version=4)
    ipv4b.get_matching_interface.return_value = object()

    with pytest.raises(ValueError, match='exactly one IPv4 and one IPv6'):
        hostidentity.validate_dual_stack_service_addresses(
            'DNS service', [ipv4a, ipv4b])


def test_validate_dual_stack_service_addresses_rejects_nonlocal_address():
    ipv4 = MagicMock(version=4)
    ipv4.__str__.return_value = '10.16.16.90'
    ipv4.get_matching_interface.return_value = None
    ipv6 = MagicMock(version=6)
    ipv6.__str__.return_value = '2a07:e580:a10::10'
    ipv6.get_matching_interface.return_value = object()

    with pytest.raises(ValueError, match='not configured on a local interface'):
        hostidentity.validate_dual_stack_service_addresses(
            'Directory Controller', [ipv4, ipv6])


def test_validate_distinct_service_subnets_rejects_shared_ipv4_network():
    directory_v4 = MagicMock(version=4)
    directory_v6 = MagicMock(version=6)
    dns_v4 = MagicMock(version=4)
    dns_v6 = MagicMock(version=6)

    directory_v4.get_matching_interface.return_value.ifnet.cidr = '10.0.0.0/24'
    dns_v4.get_matching_interface.return_value.ifnet.cidr = '10.0.0.0/24'
    directory_v6.get_matching_interface.return_value.ifnet.cidr = (
        '2001:db8:1::/64')
    dns_v6.get_matching_interface.return_value.ifnet.cidr = '2001:db8:2::/64'

    with pytest.raises(ValueError, match='different IPv4 subnets'):
        hostidentity.validate_distinct_service_subnets(
            [directory_v4, directory_v6], [dns_v4, dns_v6])


def test_validate_distinct_service_subnets_accepts_distinct_networks():
    addresses = [MagicMock(version=4), MagicMock(version=6),
                 MagicMock(version=4), MagicMock(version=6)]
    networks = ['10.0.0.0/24', '2001:db8:1::/64',
                '10.0.1.0/24', '2001:db8:2::/64']
    for address, network in zip(addresses, networks):
        address.get_matching_interface.return_value.ifnet.cidr = network

    hostidentity.validate_distinct_service_subnets(
        addresses[:2], addresses[2:])


def test_verify_machine_identity_accepts_typed_principals():
    target = f'host/{SYSTEM_HOST}@{REALM}'
    source = f'host/{IPA_HOST}@{REALM}'
    entry = MagicMock()
    entry.get.return_value = [Principal(source), Principal(target)]
    entry.single_value = {
        'krbcanonicalname': Principal(target),
        'fqdn': SYSTEM_HOST,
    }
    api_instance = MagicMock()
    api_instance.Backend.ldap2.get_entry.return_value = entry

    with patch.object(hostidentity, '_host_dn', return_value='host-dn'):
        hostidentity.verify_machine_identity(
            IPA_HOST, SYSTEM_HOST, REALM, api_instance=api_instance)


def test_service_alias_metadata_keeps_single_canonical_alias():
    canonical = f'HTTP/{IPA_HOST}@{REALM}'
    alias = f'HTTP/{SYSTEM_HOST}@{REALM}'
    entry = MagicMock()
    values = {
        'krbprincipalname': [canonical],
        'objectclass': ['top', 'ipaservice'],
    }
    entry.get.side_effect = lambda key, default=(): values.get(key, default)
    entry.single_value.get.side_effect = lambda key: {
        'krbcanonicalname': canonical,
        'ipakrbprincipalalias': None,
    }.get(key)

    ldap = MagicMock()
    ldap.find_entries.return_value = ([entry], False)
    api_instance = MagicMock()

    with patch.object(hostidentity, 'SERVICE_PRINCIPAL_PREFIXES', ('HTTP',)), \
            patch.object(hostidentity, 'DN', return_value='service-base'):
        hostidentity._add_service_principal_aliases(
            ldap, IPA_HOST, SYSTEM_HOST, REALM, api_instance)

    entry.__setitem__.assert_any_call(
        'krbprincipalname', [canonical, alias])
    entry.__setitem__.assert_any_call(
        'objectclass', ['top', 'ipaservice', 'ipakrbprincipal'])
    entry.__setitem__.assert_any_call(
        'ipakrbprincipalalias', [canonical])
    ldap.update_entry.assert_called_once_with(entry)
