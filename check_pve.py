#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_pve.py - A check plugin for Proxmox Virtual Environment (PVE).
# Copyright (C) 2018-2022  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 1.2.2
#
# ------------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ------------------------------------------------------------------------------

import sys
import re

try:
    from enum import Enum
    from datetime import datetime
    import argparse
    import requests
    import urllib3


except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)


class UnknownCheckError(Exception):
    pass


class CheckState(Enum):
    """
    Icinga check states
    """
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


def output(state, message):
    """print check result with prefix and message and exit with return code"""
    prefix = state.name
    message = '{} - {}'.format(prefix, message)

    print(message)
    sys.exit(state.value)


class CheckPVE:
    """Multi check command for monitoring of PVE"""
    VERSION = '1.2.2'
    API_URL = 'https://{hostname}:{port}/api2/json/{command}'
    UNIT_SCALE = {
        "GB": 10**9,
        "MB": 10**6,
        "KB": 10**3,
        "GiB": 2**30,
        "MiB": 2**20,
        "KiB": 2**10,
        "B": 1
    }

    def _get_url(self, command):
        return self.API_URL.format(
            hostname=self._api["host"],
            command=command,
            port=self._api["port"])

    def _request(self, url, method='get', data=None, params=None):
        response = None
        try:
            if method == 'post':
                response = requests.post(
                    url,
                    verify=not self._api.get("insecure_tls", False),
                    data=data,
                    timeout=5
                )
            elif method == 'get':
                response = requests.get(
                    url,
                    verify=not self._api.get("insecure_tls", False),
                    cookies=self._api.get("cookies", {}),
                    headers=self._api.get("headers", {}),
                    params=params,
                )
            else:
                output(CheckState.CRITICAL,
                       "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            output(CheckState.UNKNOWN,
                   "Could not connect to PVE API: Connection timeout")
        except requests.exceptions.SSLError:
            output(CheckState.UNKNOWN,
                   "Could not connect to PVE API: Certificate validation failed")
        except requests.exceptions.ConnectionError:
            output(CheckState.UNKNOWN,
                   "Could not connect to PVE API: Failed to resolve hostname")

        if response.ok:
            return response.json()['data']

        message = "Could not fetch data from API: "

        if response.status_code == 401:
            message += "Could not connection to PVE API: invalid username or password"
        elif response.status_code == 403:
            message += "Access denied. Please check if API user has sufficient permissions " \
                "/ the role has been assigned."
        else:
            message += "HTTP error code was {}".format(
                response.status_code)

        output(CheckState.UNKNOWN, message)
        return {}

    def get_ticket(self, username: str, password: str):
        """get access ticket from API api"""
        url = self._get_url('access/ticket')
        data = {"username": username, "password": password}
        result = self._request(url, "post", data=data)

        return result['ticket']

    def check_api_value(self, url: str, message: str, **kwargs):
        """generic check command for simple PVE api checks"""
        result = self._request(url)
        values = {}

        key = kwargs.get("key", None)
        if key is not None and key in result:
            result = result[key]


        if isinstance(result, dict):
            usage = self._get_value(result['used'], result['total'])
            used = self._get_value(result['used'])
            total = self._get_value(result['total'])

            values = {"usage": usage, "used": used}
            default = "usage"

            self._add_perfdata('usage', usage)
            self._add_perfdata('used', used,
                default_threshold=False, max=total, unit=self._unit)
        else:
            metric = kwargs.get('perfkey', 'usage')
            usage = round(float(result) * 100, 2)

            values = {"usage": usage}
            default = metric

            self._add_perfdata(metric, usage)

        if self._options.get("values_bytes", False):
            message += ' {} {}'.format(used, self._unit)
        else:
            message += ' {} {}'.format(usage, '%')

        self._check_thresholds(values, message, default_threshold=default)

    def _check_vm_status(self, idx, node=None, **kwargs):
        url = self._get_url('cluster/resources', )
        data = self._request(url, params={'type': 'vm'})

        expected_state = kwargs.get("expected_state", "running")
        ignore_state = kwargs.get("ignore_state", False)
        only_state = kwargs.get("only_state", False)

        found = False
        for virtual_machine in data:
            if idx in [virtual_machine['name'], virtual_machine['vmid']]:
                # Check if VM (default) or LXC
                vm_type = "VM"
                if virtual_machine['type'] == 'lxc':
                    vm_type = "LXC"

                if virtual_machine['status'] != expected_state:
                    self.check_message = "{} '{}' is {} (expected: {})" .format(
                        vm_type, virtual_machine['name'],
                        virtual_machine['status'], expected_state)
                    if not ignore_state:
                        self.check_result = CheckState.CRITICAL
                else:
                    if node and node != virtual_machine['node']:
                        self.check_message = "{} '{}' is {}".format(
                            vm_type,
                            virtual_machine['name'],
                            expected_state)
                        self.check_message += ", but located on node '{}' instead of '{}'".format(
                            virtual_machine['node'], node)
                        self.check_result = CheckState.WARNING
                    else:
                        self.check_message = "{} '{}' is {} on node '{}'".format(
                            vm_type,
                            virtual_machine['name'],
                            expected_state,
                            virtual_machine['node'])

                if virtual_machine['status'] == 'running' and not only_state:
                    cpu = round(virtual_machine['cpu'] * 100, 2)
                    self._add_perfdata("cpu", cpu)

                    if self._options.get("values_bytes", False):
                        memory = self._scale_value(
                            virtual_machine['mem'], self._unit)
                        self._add_perfdata(
                            "memory", memory,
                            unit=self._unit,
                            default_threshold=False,
                            max=self._scale_value(virtual_machine['maxmem'], self._unit))

                    else:
                        memory = self._get_value(
                            virtual_machine['mem'],
                            virtual_machine['maxmem'])
                        self._add_perfdata("memory", memory, default_threshold=False)

                    self._check_thresholds(
                        {"cpu": cpu, "memory": memory},
                        self.check_message,
                        default_threshold="cpu")

                found = True
                break

        if not found:
            self.check_message = "VM or LXC '{}' not found".format(idx)
            self.check_result = CheckState.WARNING

    def _check_disks(self, node: str, ignore_disks: list = None):
        url = self._get_url('nodes/{}/disks'.format(node))

        values = {}

        failed = []
        unknown = []
        disks = self._request(url + '/list')
        for disk in disks:
            name = disk['devpath'].replace('/dev/', '')

            if isinstance(ignore_disks, list) and name in ignore_disks:
                continue

            if disk['health'] == 'UNKNOWN':
                self.check_result = CheckState.WARNING
                unknown.append(
                    {"serial": disk["serial"], "device": disk['devpath']})

            elif disk['health'] not in ('PASSED', 'OK'):
                self.check_result = CheckState.WARNING
                failed.append(
                    {"serial": disk["serial"], "device": disk['devpath']})

            if disk['wearout'] != 'N/A':
                key = 'wearout_{}'.format(name)
                values[key] = disk['wearout']
                self._add_perfdata(key, disk['wearout'])

        if failed:
            self.check_message = "{} of {} disks failed the health test:\n".format(
                len(failed), len(disks))
            for disk in failed:
                self.check_message += "- {} with serial '{}'\n".format(
                    disk['device'], disk['serial'])

        if unknown:
            self.check_message += "{} of {} disks have unknown health status:\n".format(
                len(unknown), len(disks))
            for disk in unknown:
                self.check_message += "- {} with serial '{}'\n".format(
                    disk['device'], disk['serial'])

        if not failed and not unknown:
            self.check_message = "All disks are healthy"

        message_error = "wearout "
        self._check_thresholds(values, self.check_message, default_threshold=list(values.keys()))

    def _check_replication(self, node: str, vmid: int = None):
        url = self._get_url('nodes/{}/replication'.format(node))

        if vmid is not None:
            data = self._request(url, params={'guest': vmid})
        else:
            data = self._request(url)

        failed_jobs = []  # format: [{guest: str, fail_count: int, error: str}]
        performance_data = []

        for job in data:
            if job['fail_count'] > 0:
                failed_jobs.append(
                    {'guest': job['guest'], 'fail_count': job['fail_count'], 'error': job['error']})
            else:
                performance_data.append(
                    {'id': job['id'], 'duration': job['duration']})

        if len(failed_jobs) > 0:
            message = "Failed replication jobs on {}: ".format(node)
            for job in failed_jobs:
                message = message + \
                    "GUEST: {j[guest]}, FAIL_COUNT: {j[fail_count]}, ERROR: {j[error]} ; ".format(
                        j=job)
            self.check_message = message
            self.check_result = CheckState.WARNING
        else:
            self.check_message = "No failed replication jobs on {}".format(
                node)
            self.check_result = CheckState.OK

        if len(performance_data) > 0:
            for metric in performance_data:
                self._add_perfdata(
                    'duration_' + metric['id'], metric['duration'], unit='s')

    def _check_services(self, node: str):
        url = self._get_url('nodes/{}/services'.format(node))
        data = self._request(url)

        failed = {}
        for service in data:
            if service['state'] != 'running' \
                    and service.get('active-state', 'active') == 'active' \
                    and service['name'] not in self._options.get("ignore_services", []):
                failed[service['name']] = service['desc']

        if failed:
            self.check_result = CheckState.CRITICAL
            message = "{} services are not running:\n\n".format(len(failed))
            message += "\n".join(['- {} ({}) is not running'.format(name, desc)
                                 for name, desc in failed.items()])
            self.check_message = message
        else:
            self.check_message = "All services are running"

    def _check_subscription(self, node: str):
        url = self._get_url('nodes/{}/subscription'.format(node))
        data = self._request(url)

        if data['status'] == 'NotFound':
            self.check_result = CheckState.WARNING
            self.check_message = "No valid subscription found"
        if data['status'] == 'Inactive':
            self.check_result = CheckState.CRITICAL
            self.check_message = "Subscription expired"
        elif data['status'] == 'Active':
            subscription_due_date = data['nextduedate']
            subscription_product_name = data['productname']

            date_expire = datetime.strptime(subscription_due_date, '%Y-%m-%d')
            date_today = datetime.today()
            delta = (date_expire - date_today).days

            message = '{} is valid until {}'.format(
                subscription_product_name,
                subscription_due_date)
            message_warning_critical = '{} will expire in {} days ({})'.format(
                subscription_product_name,
                delta,
                subscription_due_date)

            self._check_thresholds({"delta": delta}, message,
                                   message_warning=message_warning_critical,
                                   message_critical=message_warning_critical,
                                   lower_value=True)

    def _check_updates(self, node: str):
        url = self._get_url('nodes/{}/apt/update'.format(node))
        count = len(self._request(url))

        if count:
            self.check_result = CheckState.WARNING
            msg = "{} pending update"
            if count > 1:
                msg += "s"
            self.check_message = msg.format(count)
        else:
            self.check_message = "System up to date"

    def _check_cluster_status(self):
        url = self._get_url('cluster/status')
        data = self._request(url)

        nodes_online = []
        nodes_offline = []
        nodes_count = 0
        quorate = None
        cluster_name = ''
        for elem in data:
            if elem['type'] == 'cluster':
                quorate = elem['quorate']
                cluster_name = elem['name']
            elif elem['type'] == 'node':
                nodes_count += 1
                if elem['online']:
                    nodes_online.append(elem['name'])
                else:
                    nodes_offline.append(elem['name'])

        if quorate is None:
            self.check_message = 'No cluster configuration found'
            return

        if quorate:
            nodes_online_count = len(nodes_online)

            if nodes_count > nodes_online_count:
                self.check_result = CheckState.WARNING
                self.check_message = "Cluster '{}' is healthy, but {} node(s) offline:\n'".format(
                    cluster_name, len(nodes_offline))
                for node in nodes_offline:
                    self.check_message += "- {}\n".format(node)
            else:
                self.check_message = "Cluster '{}' is healthy'".format(
                    cluster_name)

            self._add_perfdata('nodes_total', nodes_count, unit='')
            self._add_perfdata('nodes_online', nodes_online_count, unit='')
        else:
            self.check_result = CheckState.CRITICAL
            self.check_message = 'Cluster is unhealthy - no quorum'

    def _zfs_fragmentation_process_pool(self, name: str, data, warnings, critical):
        key = "fragmentation"
        if name is None:
            key += '_{}'.format(data['name'])
        self._add_perfdata(key, data['frag'])

        threshold_name = "fragmentation_{}".format(data['name'])
        threshold_warning = self._threshold_warning(threshold_name)
        threshold_critical = self._threshold_critical(threshold_name)

        if threshold_critical is not None and data['frag'] > threshold_critical:
            critical.append(data)
        elif threshold_warning is not None and data['frag'] > threshold_warning:
            warnings.append(data)

    def _check_zfs_fragmentation(self, node: str, name: str = None):
        url = self._get_url('nodes/{}/disks/zfs'.format(node))
        data = self._request(url)

        warnings = []
        critical = []
        found = name is None
        for pool in data:
            found = found or name == pool['name']
            if (name is not None and name == pool['name']) or name is None:
                self._zfs_fragmentation_process_pool(
                    name, pool, warnings, critical)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch fragmentation of ZFS pool '{}'".format(
                name)
            return

        self.check_result = CheckState.OK
        if name is not None:
            self.check_message = "Fragmentation of ZFS pool '{}' is OK".format(
                name)
        else:
            self.check_message = "Fragmentation of all ZFS pools is OK"

        if warnings or critical:
            value = None
            if critical:
                self.check_result = CheckState.CRITICAL
                if name is not None:
                    value = critical[0]['frag']
            else:
                self.check_result = CheckState.WARNING
                if name is not None:
                    value = warnings[0]['frag']

            if name is not None:
                self.check_message = "Fragmentation of ZFS pool '{}' is above thresholds: {} %" \
                    .format(name, value)
            else:
                message = "{} of {} ZFS pools are above fragmentation thresholds:\n\n".format(
                    len(warnings) + len(critical), len(data))
                message += "\n".join(
                    ['- {} ({} %) is CRITICAL\n'.format(pool['name'], pool['frag'])
                     for pool in critical])
                message += "\n".join(
                    ['- {} ({} %) is WARNING\n'.format(pool['name'], pool['frag'])
                     for pool in warnings])
                self.check_message = message

    def _check_zfs_health(self, node: str, name=None):
        url = self._get_url('nodes/{}/disks/zfs'.format(node))
        data = self._request(url)

        unhealthy = []
        found = name is None
        healthy_conditions = ['online']
        for pool in data:
            found = found or name == pool['name']
            if (name is not None and name == pool['name']) or name is None:
                if pool['health'].lower() not in healthy_conditions:
                    unhealthy.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch health of ZFS pool '{}'".format(
                name)
        else:
            if unhealthy:
                self.check_result = CheckState.CRITICAL
                message = "{} ZFS pools are not healthy:\n\n".format(
                    len(unhealthy))
                message += "\n".join(['- {} ({}) is not healthy'.format(
                    pool['name'],
                    pool['health']) for pool in unhealthy])
                self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = "ZFS pool '{}' is healthy".format(
                        name)
                else:
                    self.check_message = "All ZFS pools are healthy"

    def _check_ceph_health(self):
        url = self._get_url('cluster/ceph/status')
        data = self._request(url)
        ceph_health = data.get('health', {})

        if 'status' not in ceph_health:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch Ceph status from API. " \
                                 "Check the output of 'pvesh get cluster/ceph' on your node"
            return

        if ceph_health['status'] == 'HEALTH_OK':
            self.check_result = CheckState.OK
            self.check_message = "Ceph Cluster is healthy"
        elif ceph_health['status'] == 'HEALTH_WARN':
            self.check_result = CheckState.WARNING
            self.check_message = "Ceph Cluster is in warning state"
        elif ceph_health['status'] == 'HEALTH_CRIT':
            self.check_result = CheckState.CRITICAL
            self.check_message = "Ceph Cluster is in critical state"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Ceph Cluster is in unknown state"

    def _check_storage(self, node: str, name: str):
        # check if storage exists
        url = self._get_url('nodes/{}/storage'.format(node))
        data = self._request(url)

        if not any(s['storage'] == name for s in data):
            self.check_result = CheckState.CRITICAL
            self.check_message = "Storage '{}' doesn't exist on node '{}'".format(
                name, node)
            return

        url = self._get_url('nodes/{}/storage/{}/status'.format(node, name))
        self.check_api_value(url, "Usage of storage '{}' is".format(name))

    def _check_version(self, min_version=None):
        url = self._get_url('version')
        data = self._request(url)

        if not data['version']:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Unable to determine pve version"
        elif min_version and min_version > data['version']:
            self.check_result = CheckState.CRITICAL
            self.check_message = \
                "Current pve version '{}' ({}) is lower than the min. required version '{}'" \
                .format(data['version'], data['repoid'], min_version)
        else:
            self.check_message = "Your pve instance version '{}' ({}) is up to date" \
                .format(data['version'], data['repoid'])

    def _check_memory(self, node: str):
        url = self._get_url('nodes/{}/status'.format(node))
        self.check_api_value(url, 'Memory usage is', key='memory')

    def _check_swap(self, node: str):
        url = self._get_url('nodes/{}/status'.format(node))
        self.check_api_value(url, 'Swap usage is', key='swap')

    def _check_cpu(self, node: str):
        url = self._get_url('nodes/{}/status'.format(node))
        self.check_api_value(url, 'CPU usage is', key='cpu')

    def _check_io_wait(self, node: str):
        url = self._get_url('nodes/{}/status'.format(node))
        self.check_api_value(url, 'IO wait is', key='wait', perfkey='wait')

    def _compare_values(self, value1: float, value2: float, lower: bool = False):
        if lower:
            return value1 < value2

        return value1 > value2

    def _check_thresholds(self, values, message, **kwargs):
        message_warning = kwargs.get("message_warning", message)
        message_critical = kwargs.get("message_critical", message)
        lower_value = kwargs.get("lower_value", False)
        default_threshold = kwargs.get("default_threshold", [])

        if not isinstance(default_threshold, list):
            default_threshold = [default_threshold]

        if len(values) == 1:
            default_threshold = [list(values.keys())[0]]

        is_warning = False
        is_critical = False

        for metric, value in values.items():
            value_warning = self._threshold_warning(metric, metric in default_threshold)
            if value_warning is not None:
                is_warning = is_warning or self._compare_values(
                    value, value_warning, lower_value)

            value_critical = self._threshold_critical(metric, metric in default_threshold)
            if value_critical is not None:
                is_critical = is_critical or self._compare_values(
                    value, value_critical, lower_value)

            print(metric, value, value_warning, value_critical)

        if is_critical:
            self.check_result = CheckState.CRITICAL
            self.check_message = message_critical
        elif is_warning:
            self.check_result = CheckState.WARNING
            self.check_message = message_warning
        else:
            self.check_message = message

    @staticmethod
    def _scale_value(value: float, unit: str):
        if unit is not None and unit in CheckPVE.UNIT_SCALE:
            return value / CheckPVE.UNIT_SCALE[unit]

        return value

    @property
    def _unit(self):
        # default value is "MiB" in order to keep compability with v1.2.x
        return self._options.get("unit", "MiB")

    def __threshold(self, name: str, threshold_type: str, default: bool = True):
        threshold_name = "threshold_" + threshold_type
        if threshold_name not in self._options:
            return None

        threshold = self._options[threshold_name]

        if isinstance(threshold, dict) and name in threshold:
            return threshold[name]

        if isinstance(threshold, (float, int)) and default:
            return threshold

        return None

        # return threshold.get(name, threshold.get(None, None) if default else None)

    def _threshold_warning(self, name: str, default: bool = True):
        return self.__threshold(name, "warning", default)

    def _threshold_critical(self, name: str, default: bool = True):
        return self.__threshold(name, "critical", default)

    def _get_value(self, value, total=None):
        value = float(value)

        if total:
            value /= float(total) / 100
        else:
            value = self._scale_value(value, self._unit)

        return round(value, 2)

    def _add_perfdata(self, name, value, **kwargs):
        unit = kwargs.get('unit', '%')
        ignore_thresholds = kwargs.get('ignore_thresholds', False)
        default_threshold = kwargs.get("default_threshold", True)

        perfdata = '{}={}{}'.format(name, value, unit)

        threshold_warning = self._threshold_warning(name, default_threshold)
        perfdata += ';'
        if not ignore_thresholds and threshold_warning is not None:
            perfdata += str(threshold_warning)

        threshold_critical = self._threshold_critical(name, default_threshold)
        perfdata += ';'
        if (not ignore_thresholds or default_threshold) and threshold_critical is not None:
            perfdata += str(threshold_critical)

        perfdata += ';{}'.format(kwargs.get('min', 0))
        perfdata += ';{}'.format(kwargs.get('max', ''))

        self.__perfdata.append(perfdata)

    @property
    def _perfdata_string(self):
        perfdata = ''

        if self.__perfdata:
            perfdata = '|'
            perfdata += ' '.join(self.__perfdata)

        return perfdata

    def check_output(self):
        """pre-process check output with message and perfdata if present"""
        message = self.check_message
        if self.__perfdata:
            message += self._perfdata_string

        output(self.check_result, message)

    def check(self, mode: str, options: dict = {}):
        """choose check command to run based on specfied mode"""
        self.check_result = CheckState.OK
        self._options = options

        def vm_status_helper():
            idx = options.get("name", options.get("vmid", None))
            parameters = {"only_state": mode == 'vm_status'}

            if "expected_vm_state" in options:
                parameters['expected_state'] = options["expected_vm_state"]
            if "ignore_vm_state" in options:
                parameters["ignore_state"] = options["ignore_vm_state"]
            if "node" in options:
                parameters['node'] = options["node"]

            self._check_vm_status(idx, **parameters)

        checks = {
            "cluster": self._check_cluster_status,
            "version": lambda: self._check_version(options.get("min_version", None)),
            "cpu": lambda: self._check_cpu(options["node"]),
            "memory": lambda: self._check_memory(options["node"]),
            "disk-health": lambda: self._check_disks(options["node"], options.get("ignore_disks", [])),
            "swap": lambda: self._check_swap(options["node"]),
            "io_wait": lambda: self._check_io_wait(options["node"]),
            "io-wait": lambda: self._check_io_wait(options["node"]),
            "services": lambda: self._check_services(options["node"]),
            "updates": lambda: self._check_updates(options["node"]),
            "subscription": lambda: self._check_subscription(options["node"]),
            "storage": lambda: self._check_storage(options["node"], options["name"]),
            "vm": vm_status_helper,
            "vm_status": vm_status_helper,
            "vm-status": vm_status_helper,
            "replication": lambda: self._check_replication(options["node"], options.get("vmid", None)),
            "ceph-health": self._check_ceph_health,
            "zfs-health": lambda: self._check_zfs_health(options["node"], options["name"]),
            "zfs-fragmentation": lambda: self._check_zfs_fragmentation(options["node"], options["name"])
        }

        def command_not_found():
            raise UnknownCheckError("Check mode '{}' not known".format(mode))
            # output(CheckState.UNKNOWN, "Check mode '{}' not known".format(options.mode))

        checks.get(mode, command_not_found)()

        return self.check_result

    def authentificate_token(self, username: str, token: str):
        """authentificate with username,token"""
        self._api["headers"]["Authorization"] = "PVEAPIToken={}!{}".format(
            username, token)

    def authentificate_password(self, username: str, password: str):
        """authentificate with username/password and get PVEAuthCookie"""
        self._api["cookies"]['PVEAuthCookie'] = self.get_ticket(
            username, password)

    def __init__(self, host: str, port: int = 8006, insecure_tls: bool = False):
        self.__perfdata = []
        self.check_result = CheckState.UNKNOWN
        self.check_message = ""

        self._api = {
            "headers": {},
            "cookies": {},
            "host": host,
            "port": port,
            "insecure_tls": insecure_tls
        }

        self._options = {}

        if insecure_tls:
            # disable urllib3 warning about insecure requests
            if requests.__version__ < '2.16.0':
                requests.packages.urllib3.disable_warnings(
                    requests.packages.urllib3.exceptions.InsecureRequestWarning)
            else:
                urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning)


def threshold_type(arg: str):
    """argparse compatible type helper for threshold"""
    threshold = {}

    try:
        threshold = float(arg)
    except ValueError as value_error:
        for token in arg.split(','):
            token_match = re.match("([a-z_0-9]+):([0-9.]+)", token)

            if token_match:
                threshold[token_match.group(1)] = float(token_match.group(2))
            else:
                raise argparse.ArgumentTypeError(
                    "invalid threshold format: {}".format(token)) from value_error

    return threshold


def compare_thresholds(threshold_warning: dict, threshold_critical: dict, comparator_func):
    """compare two threshold dictionaries by comparator function"""
    criteria_ok = True

    if not isinstance(threshold_warning, dict):
        threshold_warning = {None: threshold_warning}

    if not isinstance(threshold_critical, dict):
        threshold_critical = {None: threshold_critical}

    keys = set(list(threshold_warning.keys()) +
               list(threshold_critical.keys()))
    for key in keys:
        if (key in threshold_warning and key in threshold_critical)\
                or (None in threshold_warning and None in threshold_critical):
            criteria_ok = criteria_ok and comparator_func(
                threshold_warning[key], threshold_critical[key])
        elif key in threshold_warning and None in threshold_critical:
            criteria_ok = criteria_ok and comparator_func(
                threshold_warning[key], threshold_critical[None])
        elif key in threshold_critical and None in threshold_warning:
            criteria_ok = criteria_ok and comparator_func(
                threshold_warning[None], threshold_critical[key])

    return criteria_ok


def parse_args(args):
    """parse CLI args"""
    parser = argparse.ArgumentParser(
        description='Check command for PVE hosts via API')

    api_opts = parser.add_argument_group('API Options')

    api_opts.add_argument(
        "-e", "--api-endpoint",
        required=True, help="PVE api endpoint hostname")

    api_opts.add_argument(
        "--api-port", required=False,
        help="PVE api endpoint port")

    api_opts.add_argument(
        "-u", "--username", dest='api_user', required=True,
        help="PVE api user (e.g. icinga2@pve or icinga2@pam, depending on which backend "
        "you have chosen in proxmox)")

    secret_group = api_opts.add_mutually_exclusive_group(required=True)
    secret_group.add_argument(
        "-p", "--password",
        dest='api_password', help="PVE API user password")

    secret_group.add_argument(
        "-t", "--api-token", dest="api_token",
        help="PVE API token (format: TOKEN_ID=TOKEN_SECRET")

    api_opts.add_argument(
        "-k", "--insecure", dest='api_insecure', action='store_true', default=False,
        help="Don't verify HTTPS certificate")

    api_opts.set_defaults(api_port=8006)

    check_opts = parser.add_argument_group('Check Options')

    check_opts.add_argument(
        "-m", "--mode",
        choices=(
            'cluster', 'version', 'cpu', 'memory', 'swap', 'storage', 'io_wait',
            'updates', 'services', 'subscription', 'vm', 'vm_status', 'replication',
            'disk-health', 'ceph-health', 'zfs-health', 'zfs-fragmentation'),
        required=True, help="Mode to use")

    check_opts.add_argument(
        '-w', '--warning', dest='threshold_warning',
        type=threshold_type, default={},
        help='Warning threshold for check value. Mutiple thresholds with name:value,name:value')

    check_opts.add_argument(
        '-c', '--critical', dest='threshold_critical',
        type=threshold_type, default={},
        help="Critical threshold for check value. "
        "Mutiple thresholds with name:value,name:value")

    check_opts.add_argument(
        '-M', dest='values_bytes', action='store_true', default=False,
        help="Values are shown in the unit which is set with --unit (if available). "
        "Thresholds are also treated in this unit")

    check_opts.add_argument(
        '--unit', choices=CheckPVE.UNIT_SCALE.keys(), default='MiB',
        help='Unit which is used for performance data and other values')

    opts, rem_args = parser.parse_known_args(args)

    # TODO: fix arguments

    check_opts.add_argument(
        '-n', '--node', dest='node',
        required=opts.mode not in ['cluster', 'vm',
                                   'vm_status', 'version', 'ceph-health'],
        help='Node to check (necessary for all modes except cluster and version)')

    if opts.mode in ["vm", "vm_status"]:
        id_group = parser.add_mutually_exclusive_group(required=True)
    else:
        id_group = parser.add_argument_group()

    id_group.add_argument(
        '--name', dest='name', required=opts.mode == "storage",
        help='Name of storage, vm, or container')

    id_group.add_argument(
        '--vmid', dest='vmid', type=int,
        help='ID of virtual machine or container')

    check_opts.add_argument(
        '--expected-vm-status', dest='expected_vm_state',
        choices=('running', 'stopped', 'paused'),
        help='Expected VM status',
        default='running')

    check_opts.add_argument(
        '--ignore-vm-status', dest='ignore_vm_state', action='store_true',
        help='Ignore VM status in checks',
        default=False)

    check_opts.add_argument(
        '--ignore-service', dest='ignore_services', action='append', metavar='NAME',
        help='Ignore service NAME in checks', default=[])

    check_opts.add_argument('--ignore-disk', dest='ignore_disks', action='append',
                            metavar='NAME', help='Ignore disk NAME in health check', default=[])

    check_opts.add_argument(
        '-V', '--min-version', dest='min_version', type=str,
        help="The minimal pve version to check for."
        "Any version lower than this will return CRITICAL.")

    return parser.parse_args(args)


def filter_check_options(options):
    """filter check parameter from cli args"""
    filtered_options = {}
    for key, value in vars(options).items():
        if not key.startswith("api_") and key != "mode":
            filtered_options[key] = value

    return filtered_options
    # return namedtuple("CheckOptions", filtered_options.keys())(*filtered_options.values())


if __name__ == "__main__":
    cli_args: argparse.Namespace = parse_args(sys.argv[1:])
    check_options = filter_check_options(cli_args)

    if cli_args.threshold_warning and cli_args.threshold_critical:
        if cli_args.mode != 'subscription' and not compare_thresholds(
                cli_args.threshold_warning,
                cli_args.threshold_critical,
                lambda w, c: w <= c):
            output(CheckState.UNKNOWN,
                   "critical threshold must be greater than warning threshold")
        elif cli_args.mode == 'subscription' and not compare_thresholds(
                cli_args.threshold_warning,
                cli_args.threshold_critical,
                lambda w, c: w >= c):
            output(CheckState.UNKNOWN,
                   "critical threshold must be lower than warning threshold")

    pve = CheckPVE(
        host=cli_args.api_endpoint,
        port=cli_args.api_port,
        insecure_tls=cli_args.api_insecure)

    if cli_args.api_token:
        pve.authentificate_token(cli_args.api_user, cli_args.api_token)
    elif cli_args.api_password:
        pve.authentificate_password(cli_args.api_user, cli_args.api_password)

    try:
        pve.check(cli_args.mode, check_options)
        pve.check_output()
    except UnknownCheckError as error:
        output(CheckState.UNKNOWN, str(error))
