#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Helpers for separating machine identity from IPA server identity.

FreeIPA traditionally uses one FQDN for both the operating system host and
all IPA server services.  The helpers in this module implement a narrow
compatibility mode: IPA services retain the canonical IPA server hostname,
while the machine host object is finalized under a different system hostname.
"""

from __future__ import absolute_import

import logging

import SSSDConfig
from subprocess import CalledProcessError

from ipalib import api, errors
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import ipautil
from ipapython.dn import DN
from ipapython.ipachangeconf import IPAChangeConf


logger = logging.getLogger(__name__)

# Service principals created by the server installer whose keys are tied to
# the server host object in the legacy split-hostname deployment model.
SERVICE_PRINCIPAL_PREFIXES = (
    'HTTP',
    'cifs',
    'dogtag',
    'ipa-dnskeysyncd',
    'ldap',
)

# 389-DS updates member, uniqueMember, owner and seeAlso on modrdn by
# default. FreeIPA stores host DNs in additional relation attributes, so the
# split-hostname transition updates all host-relevant DN references explicitly.
def validate_dual_stack_service_addresses(label, addresses):
    """Validate one explicit IPv4 + one explicit IPv6 local service address."""
    if not addresses:
        raise ValueError(
            '{0} requires exactly one IPv4 and one IPv6 address'.format(label)
        )

    addresses = list(addresses)
    ipv4 = [address for address in addresses if address.version == 4]
    ipv6 = [address for address in addresses if address.version == 6]
    if len(addresses) != 2 or len(ipv4) != 1 or len(ipv6) != 1:
        raise ValueError(
            '{0} requires exactly one IPv4 and one IPv6 address'.format(label)
        )

    missing = [
        address for address in addresses
        if not address.get_matching_interface()
    ]
    if missing:
        raise ValueError(
            '{0} address(es) are not configured on a local interface: {1}'
            .format(label, ', '.join(str(address) for address in missing))
        )

    return ipv4[0], ipv6[0]


def validate_distinct_service_subnets(
        directory_addresses, dns_addresses):
    """Require Directory and DNS endpoints to live in distinct L3 networks."""
    for directory_address, dns_address in zip(
            directory_addresses, dns_addresses):
        directory_interface = directory_address.get_matching_interface()
        dns_interface = dns_address.get_matching_interface()
        if directory_interface is None or dns_interface is None:
            raise ValueError('service address is not configured locally')
        if directory_interface.ifnet.cidr == dns_interface.ifnet.cidr:
            raise ValueError(
                'Directory Controller and DNS service must use different {0} '
                'subnets'.format(
                    'IPv4' if directory_address.version == 4 else 'IPv6'))


HOST_DN_REFERENCE_ATTRIBUTES = (
    'member',
    'uniquemember',
    'owner',
    'seealso',
    'managedby',
    'memberhost',
    'sourcehost',
    'ipaallowedtoperform',
    'ipaowner',
    'membermanager',
    'enrolledby',
)


def _host_principal(hostname, realm):
    return 'host/{0}@{1}'.format(hostname, realm)


def _service_principal(prefix, hostname, realm):
    return '{0}/{1}@{2}'.format(prefix, hostname, realm)


def _host_dn(hostname, api_instance):
    return DN(
        ('fqdn', hostname),
        api_instance.env.container_host,
        api_instance.env.basedn,
    )


def _replace_dn_references(ldap, basedn, old_dn, new_dn):
    """Replace remaining references to a host DN after LDAP modrdn."""
    filters = [
        ldap.make_filter_from_attr(attribute, old_dn)
        for attribute in HOST_DN_REFERENCE_ATTRIBUTES
    ]
    search_filter = ldap.combine_filters(filters, ldap.MATCH_ANY)
    try:
        entries, _truncated = ldap.find_entries(
            filter=search_filter,
            attrs_list=list(HOST_DN_REFERENCE_ATTRIBUTES),
            base_dn=basedn,
        )
    except errors.NotFound:
        return

    reference_attrs = {
        attribute.lower() for attribute in HOST_DN_REFERENCE_ATTRIBUTES
    }
    for entry in entries:
        changed = False
        for attr_name in list(entry):
            base_name = attr_name.lower().split(';', 1)[0]
            if base_name not in reference_attrs:
                continue
            values = list(entry.get(attr_name, ()))
            replaced = [
                new_dn if value == old_dn else value for value in values
            ]
            if replaced != values:
                entry[attr_name] = replaced
                changed = True
        if changed:
            ldap.update_entry(entry)


def transition_host_entry(
        ldap, source_hostname, target_hostname, realm, api_instance):
    """Rename a host entry while preserving source and target principals."""
    old_dn = _host_dn(source_hostname, api_instance)
    new_dn = _host_dn(target_hostname, api_instance)

    move_required = old_dn != new_dn
    try:
        entry = ldap.get_entry(old_dn)
    except errors.NotFound:
        try:
            entry = ldap.get_entry(new_dn)
        except errors.NotFound:
            raise RuntimeError(
                'Neither source host {0} nor target host {1} exists in LDAP'
                .format(source_hostname, target_hostname)
            )
        move_required = False
    else:
        if move_required:
            try:
                ldap.get_entry(new_dn)
            except errors.NotFound:
                pass
            else:
                raise RuntimeError(
                    'Cannot finalize host identity: target host {0} already exists'
                    .format(target_hostname)
                )

    source_principal = _host_principal(source_hostname, realm)
    target_principal = _host_principal(target_hostname, realm)
    principals = list(entry.get('krbprincipalname', ()))
    principal_names = {str(value) for value in principals}
    for principal in (source_principal, target_principal):
        if principal not in principal_names:
            principals.append(principal)
            principal_names.add(principal)

    entry['krbprincipalname'] = principals
    entry['krbcanonicalname'] = [target_principal]
    entry['cn'] = [target_hostname]
    entry['serverhostname'] = [target_hostname.split('.', 1)[0]]
    try:
        ldap.update_entry(entry)
    except errors.EmptyModlist:
        pass

    if move_required:
        ldap.move_entry(old_dn, new_dn)

        _replace_dn_references(
            ldap, api_instance.env.basedn, old_dn, new_dn)

    entry = ldap.get_entry(new_dn)
    if old_dn in entry.get('managedby', ()):
        entry['managedby'] = [
            new_dn if value == old_dn else value
            for value in entry['managedby']
        ]
        ldap.update_entry(entry)
    return entry


def _add_service_principal_aliases(
        ldap, ipa_hostname, system_hostname, realm, api_instance):
    service_base = DN(
        api_instance.env.container_service,
        api_instance.env.basedn,
    )

    for prefix in SERVICE_PRINCIPAL_PREFIXES:
        canonical = _service_principal(prefix, ipa_hostname, realm)
        alias = _service_principal(prefix, system_hostname, realm)
        search_filter = ldap.make_filter({'krbprincipalname': canonical})
        try:
            entries, _truncated = ldap.find_entries(
                filter=search_filter,
                attrs_list=['krbprincipalname', 'krbcanonicalname'],
                base_dn=service_base,
            )
        except errors.NotFound:
            # Optional services (DNS, AD trust, Dogtag) may not be installed.
            continue

        if len(entries) != 1:
            raise RuntimeError(
                'Expected exactly one service entry for {0}'.format(canonical)
            )
        entry = entries[0]
        principals = list(entry.get('krbprincipalname', ()))
        principal_names = {str(value) for value in principals}
        if alias not in principal_names:
            principals.append(alias)
            entry['krbprincipalname'] = principals
            ldap.update_entry(entry)


def _persist_hostnames(ipa_hostname, system_hostname, fstore=None):
    if fstore is not None and not fstore.has_file(paths.IPA_DEFAULT_CONF):
        fstore.backup_file(paths.IPA_DEFAULT_CONF)

    conf = IPAChangeConf('IPA split hostname')
    conf.setOptionAssignment(' = ')
    conf.setSectionNameDelimiters(('[', ']'))
    conf.changeConf(
        paths.IPA_DEFAULT_CONF,
        [conf.setSection('global', [
            conf.setOption('host', ipa_hostname),
            conf.setOption('system_hostname', system_hostname),
        ])],
    )


def _set_sssd_hostname(system_hostname, expected_hostname=None):
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()

    selected = None
    for name in sssdconfig.list_active_domains():
        domain = sssdconfig.get_domain(name)
        try:
            hostname = domain.get_option('ipa_hostname')
        except SSSDConfig.NoOptionError:
            continue
        if (expected_hostname is None or
                hostname in {expected_hostname, system_hostname}):
            selected = domain
            break

    if selected is None:
        raise RuntimeError("Couldn't find IPA domain in sssd.conf")

    selected.set_option('ipa_hostname', system_hostname)
    sssdconfig.save_domain(selected)
    sssdconfig.write()

    sssd = services.service('sssd', api)
    try:
        sssd.restart()
    except CalledProcessError:
        logger.warning('SSSD service restart was unsuccessful.')


def _set_krb5_machine_mapping(
        system_hostname, realm, ipa_domain):
    """Map the machine hostname and its DNS domain to the IPA realm."""
    krbconf = IPAChangeConf("IPA split hostname")
    krbconf.setOptionAssignment((" = ", " "))
    krbconf.setSectionNameDelimiters(("[", "]"))
    krbconf.setSubSectionDelimiters(("{", "}"))
    krbconf.setIndent(("", "  ", "    "))

    domain = system_hostname.partition('.')[2]
    mappings = [krbconf.setOption(system_hostname, realm)]
    if domain and domain != ipa_domain:
        mappings.extend([
            krbconf.setOption('.{}'.format(domain), realm),
            krbconf.setOption(domain, realm),
        ])

    krbconf.changeConf(
        paths.KRB5_FREEIPA,
        [krbconf.setSection('domain_realm', mappings)],
    )


def _ensure_local_host_keytab(hostname, realm, api_instance):
    """Append the canonical machine host key without rotating it."""
    ipautil.run([
        paths.IPA_GETKEYTAB,
        '-r',
        '-p', _host_principal(hostname, realm),
        '-k', paths.KRB5_KEYTAB,
        '-H', api_instance.env.ldap_uri,
        '-Y', 'EXTERNAL',
    ])


def verify_machine_identity(
        ipa_hostname, system_hostname, realm, api_instance=api):
    """Verify the LDAP invariants established by finalization."""
    ldap = api_instance.Backend.ldap2
    entry = ldap.get_entry(_host_dn(system_hostname, api_instance))
    target_principal = _host_principal(system_hostname, realm)
    ipa_principal = _host_principal(ipa_hostname, realm)
    principals = {str(value) for value in entry.get('krbprincipalname', ())}

    if target_principal not in principals or ipa_principal not in principals:
        raise RuntimeError('Host principal aliases are incomplete')
    canonical = entry.single_value.get('krbcanonicalname')
    if canonical is None or str(canonical) != target_principal:
        raise RuntimeError('System host principal is not canonical')
    if entry.single_value.get('fqdn') != system_hostname:
        raise RuntimeError('Host entry FQDN was not finalized')


def finalize_machine_identity(
        ipa_hostname, system_hostname, realm, fstore=None,
        api_instance=api):
    """Finalize a server installed under an IPA service hostname.

    IPA server/service discovery remains anchored on ``ipa_hostname``. Only
    the machine host object, host principal, local keytab, SSSD identity and
    operating-system hostname are moved to ``system_hostname``.

    On failure the canonical machine identity is returned to the stock
    single-hostname state so callers never observe a half-finalized server.
    Service principal aliases that may already have been added are harmless
    and intentionally retained during rollback.
    """
    if ipa_hostname == system_hostname:
        return

    ldap = api_instance.Backend.ldap2
    transitioned = False
    sssd_changed = False
    config_changed = False
    hostname_changed = False
    added_hosts_records = []

    try:
        transition_host_entry(
            ldap, ipa_hostname, system_hostname, realm, api_instance)
        transitioned = True
        _add_service_principal_aliases(
            ldap, ipa_hostname, system_hostname, realm, api_instance)
        _ensure_local_host_keytab(
            system_hostname, realm, api_instance)
        _set_sssd_hostname(system_hostname, expected_hostname=ipa_hostname)
        sssd_changed = True
        _set_krb5_machine_mapping(
            system_hostname, realm, api_instance.env.domain)
        _persist_hostnames(ipa_hostname, system_hostname, fstore=fstore)
        config_changed = True

        directory_addresses = [
            value for value in (
                getattr(api_instance.env, 'ipa_ipv4_address', None),
                getattr(api_instance.env, 'ipa_ipv6_address', None),
            ) if value
        ]
        added_hosts_records.extend(_ensure_local_hosts_records(
            ipa_hostname, directory_addresses))

        dns_hostname = getattr(api_instance.env, 'dns_hostname', None)
        if dns_hostname:
            dns_addresses = [
                value for value in (
                    getattr(api_instance.env, 'dns_ipv4_address', None),
                    getattr(api_instance.env, 'dns_ipv6_address', None),
                ) if value
            ]
            added_hosts_records.extend(_ensure_local_hosts_records(
                dns_hostname, dns_addresses))

        tasks.set_hostname(system_hostname)
        hostname_changed = True
        verify_machine_identity(
            ipa_hostname, system_hostname, realm, api_instance=api_instance)
    except BaseException:
        logger.exception(
            'Machine identity finalization failed; restoring IPA hostname')
        if transitioned:
            try:
                transition_host_entry(
                    ldap, system_hostname, ipa_hostname, realm, api_instance)
            except Exception:
                logger.exception('Failed to restore LDAP host identity')
        if sssd_changed:
            try:
                _set_sssd_hostname(
                    ipa_hostname, expected_hostname=system_hostname)
            except Exception:
                logger.exception('Failed to restore SSSD host identity')
        if config_changed:
            try:
                # Do not restore FileStore here. During replica promotion its
                # backup is the pre-promotion client configuration, not the
                # fully installed server configuration. Revert only the two
                # split-hostname keys and preserve all server/CA settings.
                _restore_single_hostname_config(ipa_hostname, fstore=None)
            except Exception:
                logger.exception('Failed to restore IPA configuration')
        if hostname_changed or transitioned:
            try:
                tasks.set_hostname(ipa_hostname)
            except Exception:
                logger.exception('Failed to restore operating-system hostname')
        try:
            _remove_local_hosts_records(added_hosts_records)
        except Exception:
            logger.exception('Failed to roll back /etc/hosts service records')
        raise


def _restore_single_hostname_config(system_hostname, fstore=None):
    if fstore is not None and not fstore.has_file(paths.IPA_DEFAULT_CONF):
        fstore.backup_file(paths.IPA_DEFAULT_CONF)

    conf = IPAChangeConf('IPA split hostname rollback')
    conf.setOptionAssignment(' = ')
    conf.setSectionNameDelimiters(('[', ']'))
    conf.changeConf(
        paths.IPA_DEFAULT_CONF,
        [conf.setSection('global', [
            conf.setOption('host', system_hostname),
            conf.rmOption('system_hostname'),
            conf.rmOption('ipa_ipv4_address'),
            conf.rmOption('ipa_ipv6_address'),
            conf.rmOption('dns_hostname'),
            conf.rmOption('dns_ipv4_address'),
            conf.rmOption('dns_ipv6_address'),
        ])],
    )


def _ensure_local_hosts_records(hostname, addresses):
    """Add deterministic /etc/hosts entries and return lines we added."""
    with open(paths.HOSTS, 'r') as f:
        current = f.readlines()

    existing = set()
    for line in current:
        fields = line.partition('#')[0].split()
        if len(fields) > 1:
            existing.update(
                (fields[0], name) for name in fields[1:])

    added = []
    shortname = hostname.split('.', 1)[0]
    for address in addresses or ():
        address = str(address)
        if (address, hostname) in existing:
            continue
        line = '{}\t{} {}\n'.format(address, hostname, shortname)
        with open(paths.HOSTS, 'a') as f:
            f.write(line)
        added.append(line)
        existing.add((address, hostname))
    return added


def _remove_local_hosts_records(lines):
    if not lines:
        return
    remove = set(lines)
    with open(paths.HOSTS, 'r') as f:
        current = f.readlines()
    with open(paths.HOSTS, 'w') as f:
        for line in current:
            if line not in remove:
                f.write(line)


def _remove_local_host_keytab(hostname, realm):
    principal = _host_principal(hostname, realm)
    result = ipautil.run([
        paths.IPA_RMKEYTAB,
        '-p', principal,
        '-k', paths.KRB5_KEYTAB,
    ], raiseonerr=False)
    if result.returncode not in (0, 3, 5, 7):
        raise RuntimeError(
            'Failed to remove stale keytab entry for {0}'.format(principal)
        )


def _generate_remote_host_keytab(master_hostname, hostname, realm):
    """Generate a fresh host key on a remote IPA master.

    This is used only during replica preparation, before the host joins the
    ``ipaservers`` host group.  The caller must have administrative Kerberos
    credentials in the active credential cache.
    """
    ipautil.run([
        paths.IPA_GETKEYTAB,
        '-s', master_hostname,
        '-p', _host_principal(hostname, realm),
        '-k', paths.KRB5_KEYTAB,
    ])


def prepare_replica_identity(
        system_hostname, ipa_hostname, realm, master_hostname,
        remote_ldap, remote_api, fstore, sstore, service_ip_addresses=()):
    """Prepare an enrolled client for stock replica promotion.

    The remote host object and local client identity are temporarily moved to
    ``ipa_hostname`` so the unmodified replica bootstrap path once again sees
    the one-hostname model it expects.  ``finalize_machine_identity`` reverses
    the machine portion after replica installation completes.

    Administrative Kerberos credentials must be active for the remote LDAP
    rename and host key generation.
    """
    if system_hostname == ipa_hostname:
        return

    source_dn = _host_dn(system_hostname, remote_api)
    entry = remote_ldap.get_entry(source_dn, ['memberof'])
    ipaservers_dn = DN(
        ('cn', 'ipaservers'),
        remote_api.env.container_hostgroup,
        remote_api.env.basedn,
    )
    if ipaservers_dn in entry.get('memberof', ()):
        raise RuntimeError(
            'Split-hostname replica preparation requires a client host that '
            'is not already a member of the ipaservers host group'
        )

    added_hosts_records = _ensure_local_hosts_records(
        ipa_hostname, service_ip_addresses)
    transitioned = False
    key_removed = False
    key_generated = False
    try:
        transition_host_entry(
            remote_ldap,
            system_hostname,
            ipa_hostname,
            realm,
            remote_api,
        )
        transitioned = True

        _remove_local_host_keytab(system_hostname, realm)
        key_removed = True
        _generate_remote_host_keytab(
            master_hostname, ipa_hostname, realm)
        key_generated = True

        _set_sssd_hostname(
            ipa_hostname, expected_hostname=system_hostname)
        _persist_hostnames(
            ipa_hostname, system_hostname, fstore=fstore)

        if sstore.get_state('network', 'hostname') is None:
            tasks.backup_hostname(fstore, sstore)
        tasks.set_hostname(ipa_hostname)
    except BaseException:
        logger.exception(
            'Replica split-hostname preparation failed; rolling back')
        if transitioned:
            try:
                transition_host_entry(
                    remote_ldap,
                    ipa_hostname,
                    system_hostname,
                    realm,
                    remote_api,
                )
                if key_removed:
                    if key_generated:
                        _remove_local_host_keytab(ipa_hostname, realm)
                    _generate_remote_host_keytab(
                        master_hostname, system_hostname, realm)
            except Exception:
                logger.exception('Failed to roll back remote host identity')
        try:
            _set_sssd_hostname(
                system_hostname, expected_hostname=ipa_hostname)
        except Exception:
            logger.exception('Failed to roll back SSSD host identity')
        try:
            if (fstore is not None and
                    fstore.has_file(paths.IPA_DEFAULT_CONF)):
                fstore.restore_file(paths.IPA_DEFAULT_CONF)
            else:
                _restore_single_hostname_config(
                    system_hostname, fstore=None)
        except Exception:
            logger.exception('Failed to roll back IPA client configuration')
        try:
            if (sstore is not None and
                    sstore.get_state('network', 'hostname') is not None):
                tasks.restore_hostname(fstore, sstore)
            else:
                tasks.set_hostname(system_hostname)
        except Exception:
            logger.exception('Failed to roll back operating-system hostname')
        try:
            _remove_local_hosts_records(added_hosts_records)
        except Exception:
            logger.exception('Failed to roll back /etc/hosts service records')
        raise

    return added_hosts_records


def rollback_replica_identity(
        system_hostname, ipa_hostname, realm, master_hostname,
        remote_ldap, remote_api, fstore, sstore, added_hosts_records=()):
    """Return a prepared-but-not-promoted replica to its client identity."""
    transition_host_entry(
        remote_ldap, ipa_hostname, system_hostname, realm, remote_api)
    _remove_local_host_keytab(ipa_hostname, realm)
    _generate_remote_host_keytab(master_hostname, system_hostname, realm)
    _set_sssd_hostname(system_hostname, expected_hostname=ipa_hostname)

    if fstore is not None and fstore.has_file(paths.IPA_DEFAULT_CONF):
        fstore.restore_file(paths.IPA_DEFAULT_CONF)
    else:
        _restore_single_hostname_config(system_hostname, fstore=None)

    if sstore is not None and sstore.get_state('network', 'hostname') is not None:
        tasks.restore_hostname(fstore, sstore)
    else:
        tasks.set_hostname(system_hostname)
    _remove_local_hosts_records(added_hosts_records)
