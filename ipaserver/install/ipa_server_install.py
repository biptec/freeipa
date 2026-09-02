#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipapython.install import cli
from ipapython.install.core import extend_knob, knob
from ipaplatform.paths import paths
from ipaserver.install import installutils
from ipaserver.install.server import ServerMasterInstall


class CompatServerMasterInstall(ServerMasterInstall):
    all_ip_addresses = False
    nisdomain = None
    no_nisdomain = False
    no_sudo = False
    request_cert = False

    ds_password_file = knob(
        str, None,
        description=("Read the Directory Manager password from an owner-only "
                     "file instead of process arguments"),
        cli_names='--ds-password-file',
        cli_metavar='FILE',
    )

    dm_password = extend_knob(
        ServerMasterInstall.dm_password,
        cli_names=['--ds-password', '-p'],
    )

    @dm_password.default_getter
    def dm_password(self):
        if self.ds_password_file:
            return installutils.read_password_file(self.ds_password_file)
        return super(CompatServerMasterInstall, self).dm_password

    admin_password_file = knob(
        str, None,
        description=("Read the IPA admin password from an owner-only file "
                     "instead of process arguments"),
        cli_names='--admin-password-file',
        cli_metavar='FILE',
    )

    admin_password = ServerMasterInstall.admin_password
    admin_password = extend_knob(
        admin_password,
        cli_names=list(admin_password.cli_names) + ['-a'],
    )

    @admin_password.default_getter
    def admin_password(self):
        if self.admin_password_file:
            return installutils.read_password_file(self.admin_password_file)
        return super(CompatServerMasterInstall, self).admin_password

    ip_addresses = extend_knob(
        ServerMasterInstall.ip_addresses,
        description="Master Server IP Address. This option can be used "
                    "multiple times",
    )


ServerInstall = cli.install_tool(
    CompatServerMasterInstall,
    command_name='ipa-server-install',
    log_file_name=paths.IPASERVER_INSTALL_LOG,
    console_format='%(message)s',
    debug_option=True,
    verbose=True,
    uninstall_log_file_name=paths.IPASERVER_UNINSTALL_LOG,
)


def run():
    ServerInstall.run_cli()
