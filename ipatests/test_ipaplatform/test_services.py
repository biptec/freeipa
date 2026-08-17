#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
from unittest.mock import MagicMock, patch

from ipaplatform.redhat import services


def _directory_service(system_hostname):
    service = object.__new__(services.RedHatDirectoryService)
    service.api = MagicMock()
    service.api.env.system_hostname = system_hostname
    service.api.env.startup_timeout = 90
    service.service_instance = MagicMock(
        return_value='dirsrv@EXAMPLE-TEST.service')
    return service


def test_split_directory_service_waits_for_ldapi():
    service = _directory_service('node.example.test')
    with patch.object(
            services.paths, 'SLAPD_INSTANCE_SOCKET_TEMPLATE',
            '/run/slapd-%s.socket'), \
            patch.object(services.ipautil, 'wait_for_open_socket') as wait:
        with service._RedHatDirectoryService__wait(
                '', True, False) as systemd_wait:
            assert systemd_wait is False
    wait.assert_called_once_with('/run/slapd-EXAMPLE-TEST.socket', 90)


def test_normal_directory_service_keeps_systemd_wait():
    service = _directory_service(None)
    with patch.object(services.ipautil, 'wait_for_open_socket') as wait:
        with service._RedHatDirectoryService__wait(
                '', True, False) as systemd_wait:
            assert systemd_wait is True
    wait.assert_not_called()
