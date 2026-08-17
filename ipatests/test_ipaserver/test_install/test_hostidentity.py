#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import MagicMock, call, patch

import pytest

from ipalib import errors
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
