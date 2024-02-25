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
    from packaging import version
    import argparse
    import requests

except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)


class CheckState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckThreshold:
    def __init__(self, value: float):
        self.value = value

    def __eq__(self, other):
        return self.value == other.value

    def __lt__(self, other):
        return self.value < other.value

    def __le__(self, other):
        return self.value <= other.value

    def __gt__(self, other):
        return self.value > other.value

    def __ge__(self, other):
        return self.value >= other.value

    def check(self, value: float, lower: bool = False):
        if lower:
            return value < self.value
        else:
            return value > self.value

    @staticmethod
    def threshold_type(arg: str):
        thresholds = {}

        try:
            thresholds[None] = CheckThreshold(float(arg))
        except:
            for t in arg.split(','):
                m = re.match("([a-z_0-9]+):([0-9.]+)", t)

                if m:
                    thresholds[m.group(1)] = CheckThreshold(float(m.group(2)))
                else:
                    raise argparse.ArgumentTypeError(
                        "invalid threshold format: {}".format(t))

        return thresholds


class CheckPVE:
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

    def check_output(self):
        message = self.check_message
        if self.perfdata:
            message += self.get_perfdata()

        self.output(self.check_result, message)

    @staticmethod
    def output(rc, message):
        prefix = rc.name
        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(rc.value)

    def get_url(self, command):
        return self.API_URL.format(hostname=self.options.api_endpoint, command=command, port=self.options.api_port)

    def request(self, url, method='get', **kwargs):
        response = None
        try:
            if method == 'post':
                response = requests.post(
                    url,
                    verify=not self.options.api_insecure,
                    data=kwargs.get('data', None),
                    timeout=5
                )
            elif method == 'get':
                response = requests.get(
                    url,
                    verify=not self.options.api_insecure,
                    cookies=self.__cookies,
                    headers=self.__headers,
                    params=kwargs.get('params', None),
                )
            else:
                self.output(CheckState.CRITICAL, "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            self.output(CheckState.UNKNOWN, "Could not connect to PVE API: Connection timeout")
        except requests.exceptions.SSLError:
            self.output(CheckState.UNKNOWN, "Could not connect to PVE API: Certificate validation failed")
        except requests.exceptions.ConnectionError:
            self.output(CheckState.UNKNOWN, "Could not connect to PVE API: Failed to resolve hostname")

        if response.ok:
            return response.json()['data']
        else:
            message = "Could not fetch data from API: "

            if response.status_code == 401:
                message += "Could not connection to PVE API: invalid username or password"
            elif response.status_code == 403:
                message += "Access denied. Please check if API user has sufficient permissions / the role has been " \
                           "assigned."
            else:
                message += "HTTP error code was {}".format(response.status_code)

            self.output(CheckState.UNKNOWN, message)

    def get_ticket(self):
        url = self.get_url('access/ticket')
        data = {"username": self.options.api_user, "password": self.options.api_password}
        result = self.request(url, "post", data=data)

        return result['ticket']

    def check_api_value(self, url, message, **kwargs):
        result = self.request(url)
        used = None

        if 'key' in kwargs:
            result = result[kwargs.get('key')]

        if isinstance(result, (dict,)):
            used_percent = self.get_value(result['used'], result['total'])
            used = self.get_value(result['used'])
            total = self.get_value(result['total'])

            self.add_perfdata(kwargs.get('perfkey', 'usage'), used_percent)
            self.add_perfdata(kwargs.get('perfkey', 'used'), used, max=total, unit=self.options.unit)
        else:
            used_percent = round(float(result) * 100, 2)
            self.add_perfdata(kwargs.get('perfkey', 'usage'), used_percent)

        if self.options.values_mb:
            message += ' {} {}'.format(used, self.options.unit)
            value = used
        else:
            message += ' {} {}'.format(used_percent, '%')
            value = used_percent

        self.check_thresholds(value, message)

    def check_vm_status(self, idx, **kwargs):
        url = self.get_url('cluster/resources', )
        data = self.request(url, params={'type': 'vm'})

        expected_state = kwargs.get("expected_state", "running")
        only_status = kwargs.get("only_status", False)

        found = False
        for vm in data:
            if vm['name'] == idx or vm['vmid'] == idx:
                # Check if VM (default) or LXC
                vm_type = "VM"
                if vm['type'] == 'lxc':
                    vm_type = "LXC"

                if vm['status'] != expected_state:
                    self.check_message = "{} '{}' is {} (expected: {})".format(vm_type, vm['name'], vm['status'],
                                                                               expected_state)
                    if not self.options.ignore_vm_status:
                        self.check_result = CheckState.CRITICAL
                else:
                    if self.options.node and self.options.node != vm['node']:
                        self.check_message = "{} '{}' is {}, but located on node '{}' instead of '{}'" \
                            .format(vm_type, vm['name'], expected_state, vm['node'], self.options.node)
                        self.check_result = CheckState.WARNING
                    else:
                        self.check_message = "{} '{}' is {} on node '{}'" \
                            .format(vm_type, vm['name'], expected_state, vm['node'])

                if vm['status'] == 'running' and not only_status:
                    cpu = round(vm['cpu'] * 100, 2)
                    self.add_perfdata("cpu", cpu)

                    if self.options.values_mb:
                        memory = self.scale_value(vm['mem'])
                        self.add_perfdata("memory", memory, unit=self.options.unit, max=self.scale_value(vm['maxmem']))
                        disk = self.scale_value(vm['disk'])
                        self.add_perfdata("disk", disk, unit=self.options.unit, max=self.scale_value(vm['maxdisk']))

                    else:
                        memory = self.get_value(vm['mem'], vm['maxmem'])
                        self.add_perfdata("memory", memory)
                        disk = self.get_value(vm['disk'], vm['maxdisk'])
                        self.add_perfdata("disk", disk)

                    self.check_thresholds({"cpu": cpu, "memory": memory, "disk": disk}, message=self.check_message)

                found = True
                break

        if not found:
            self.check_message = "VM or LXC '{}' not found".format(idx)
            self.check_result = CheckState.WARNING

    def check_disks(self):
        url = self.get_url('nodes/{}/disks'.format(self.options.node))

        failed = []
        unknown = []
        disks = self.request(url + '/list')
        for disk in disks:
            name = disk['devpath'].replace('/dev/', '')

            if name in self.options.ignore_disks:
                continue

            if disk['health'] == 'UNKNOWN':
                self.check_result = CheckState.WARNING
                unknown.append({"serial": disk["serial"], "device": disk['devpath']})

            elif disk['health'] not in ('PASSED', 'OK'):
                self.check_result = CheckState.WARNING
                failed.append({"serial": disk["serial"], "device": disk['devpath']})

            if disk['wearout'] != 'N/A':
                self.add_perfdata('wearout_{}'.format(name), disk['wearout'])

        if failed:
            self.check_message = "{} of {} disks failed the health test:\n".format(len(failed), len(disks))
            for disk in failed:
                self.check_message += "- {} with serial '{}'\n".format(disk['device'], disk['serial'])

        if unknown:
            self.check_message += "{} of {} disks have unknown health status:\n".format(len(unknown), len(disks))
            for disk in unknown:
                self.check_message += "- {} with serial '{}'\n".format(disk['device'], disk['serial'])

        if not failed and not unknown:
            self.check_message = "All disks are healthy"

    def check_replication(self):
        url = self.get_url('nodes/{}/replication'.format(self.options.node))

        if self.options.vmid:
            data = self.request(url, params={'guest': self.options.vmid})
        else:
            data = self.request(url)

        failed_jobs = []  # format: [{guest: str, fail_count: int, error: str}]
        performance_data = []

        for job in data:
            if job['fail_count'] > 0:
                failed_jobs.append({'guest': job['guest'], 'fail_count': job['fail_count'], 'error': job['error']})
            else:
                performance_data.append({'id': job['id'], 'duration': job['duration']})

        if len(failed_jobs) > 0:
            message = "Failed replication jobs on {}: ".format(self.options.node)
            for job in failed_jobs:
                message = message + "GUEST: {j[guest]}, FAIL_COUNT: {j[fail_count]}, ERROR: {j[error]} ; ".format(j=job)
            self.check_message = message
            self.check_result = CheckState.WARNING
        else:
            self.check_message = "No failed replication jobs on {}".format(self.options.node)
            self.check_result = CheckState.OK

        if len(performance_data) > 0:
            for metric in performance_data:
                self.add_perfdata('duration_' + metric['id'], metric['duration'], unit='s')

    def check_services(self):
        url = self.get_url('nodes/{}/services'.format(self.options.node))
        data = self.request(url)

        failed = {}
        for service in data:
            if service['state'] != 'running' \
                    and service.get('active-state', 'active') == 'active' \
                    and service['name'] not in self.options.ignore_services:
                failed[service['name']] = service['desc']

        if failed:
            self.check_result = CheckState.CRITICAL
            message = "{} services are not running:\n\n".format(len(failed))
            message += "\n".join(['- {} ({}) is not running'.format(failed[i], i) for i in failed])
            self.check_message = message
        else:
            self.check_message = "All services are running"

    def check_subscription(self):
        url = self.get_url('nodes/{}/subscription'.format(self.options.node))
        data = self.request(url)

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

            self.check_thresholds(delta, message, messageWarning=message_warning_critical,
                                  messageCritical=message_warning_critical, lowerValue=True)

    def check_updates(self):
        url = self.get_url('nodes/{}/apt/update'.format(self.options.node))
        count = len(self.request(url))

        if count:
            self.check_result = CheckState.WARNING
            msg = "{} pending update"
            if count > 1:
                msg += "s"
            self.check_message = msg.format(count)
        else:
            self.check_message = "System up to date"

    def check_cluster_status(self):
        url = self.get_url('cluster/status')
        data = self.request(url)

        nodes = {}
        quorate = None
        cluster = ''
        for elem in data:
            if elem['type'] == 'cluster':
                quorate = elem['quorate']
                cluster = elem['name']
            elif elem['type'] == 'node':
                nodes[elem['name']] = elem['online']

        if quorate is None:
            self.check_message = 'No cluster configuration found'
        elif quorate:
            node_count = len(nodes)
            nodes_online_count = len({k: v for k, v in nodes.items() if v})

            if node_count > nodes_online_count:
                diff = node_count - nodes_online_count
                self.check_result = CheckState.WARNING
                self.check_message = "Cluster '{}' is healthy, but {} node(s) offline'".format(cluster, diff)
            else:
                self.check_message = "Cluster '{}' is healthy'".format(cluster)

            self.add_perfdata('nodes_total', node_count, unit='')
            self.add_perfdata('nodes_online', nodes_online_count, unit='')
        else:
            self.check_result = CheckState.CRITICAL
            self.check_message = 'Cluster is unhealthy - no quorum'

    def check_zfs_fragmentation(self, name=None):
        url = self.get_url('nodes/{}/disks/zfs'.format(self.options.node))
        data = self.request(url)

        warnings = []
        critical = []
        found = name is None
        for pool in data:
            found = found or name == pool['name']
            if (name is not None and name == pool['name']) or name is None:
                key = "fragmentation"
                if name is None:
                    key += '_{}'.format(pool['name'])
                self.add_perfdata(key, pool['frag'])

                threshold_name = "fragmentation_{}".format(pool['name'])
                threshold_warning = self.threshold_warning(threshold_name)
                threshold_critical = self.threshold_critical(threshold_name)

                if threshold_critical is not None and pool['frag'] > float(
                        threshold_critical.value):
                    critical.append(pool)
                elif threshold_warning is not None and pool['frag'] > float(
                        threshold_warning.value):
                    warnings.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch fragmentation of ZFS pool '{}'".format(name)
        else:
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
                    self.check_message = "Fragmentation of ZFS pool '{}' is above thresholds: {} %".format(name, value)
                else:
                    message = "{} of {} ZFS pools are above fragmentation thresholds:\n\n".format(
                        len(warnings) + len(critical), len(data))
                    message += "\n".join(
                        ['- {} ({} %) is CRITICAL\n'.format(pool['name'], pool['frag']) for pool in critical])
                    message += "\n".join(
                        ['- {} ({} %) is WARNING\n'.format(pool['name'], pool['frag']) for pool in warnings])
                    self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = "Fragmentation of ZFS pool '{}' is OK".format(name)
                else:
                    self.check_message = "Fragmentation of all ZFS pools is OK"

    def check_zfs_health(self, name=None):
        url = self.get_url('nodes/{}/disks/zfs'.format(self.options.node))
        data = self.request(url)

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
            self.check_message = "Could not fetch health of ZFS pool '{}'".format(name)
        else:
            if unhealthy:
                self.check_result = CheckState.CRITICAL
                message = "{} ZFS pools are not healthy:\n\n".format(len(unhealthy))
                message += "\n".join(
                    ['- {} ({}) is not healthy'.format(pool['name'], pool['health']) for pool in unhealthy])
                self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = "ZFS pool '{}' is healthy".format(name)
                else:
                    self.check_message = "All ZFS pools are healthy"

    def check_ceph_health(self):
        url = self.get_url('cluster/ceph/status')
        data = self.request(url)
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

    def check_storage(self, name):
        # check if storage exists
        url = self.get_url('nodes/{}/storage'.format(self.options.node))
        data = self.request(url)

        if not any(s['storage'] == name for s in data):
            self.check_result = CheckState.CRITICAL
            self.check_message = "Storage '{}' doesn't exist on node '{}'".format(name, self.options.node)
            return

        url = self.get_url('nodes/{}/storage/{}/status'.format(self.options.node, name))
        self.check_api_value(url, "Usage of storage '{}' is".format(name))

    def check_version(self):
        url = self.get_url('version')
        data = self.request(url)
        if not data['version']:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Unable to determine pve version"
        elif self.options.min_version and version.parse(self.options.min_version) > version.parse(data['version']):
            self.check_result = CheckState.CRITICAL
            self.check_message = "Current pve version '{}' ({}) is lower than the min. required version '{}'".format(
                data['version'], data['repoid'], self.options.min_version)
        else:
            self.check_message = "Your pve instance version '{}' ({}) is up to date".format(data['version'],
                                                                                            data['repoid'])

    def check_memory(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'Memory usage is', key='memory')

    def check_swap(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'Swap usage is', key='swap')

    def check_cpu(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'CPU usage is', key='cpu')

    def check_io_wait(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'IO wait is', key='wait', perfkey='wait')

    def check_thresholds(self, value, message, **kwargs):
        is_warning = False
        is_critical = False

        if not isinstance(value, dict):
            value = { None: value }

        for metric, value in value.items():
            value_warning = self.threshold_warning(metric)
            if value_warning is not None:
                is_warning = is_warning or value_warning.check(value, kwargs.get('lowerValue', False))

            value_critical = self.threshold_critical(metric)
            if value_critical is not None:
                is_critical = is_critical or value_critical.check(value, kwargs.get('lowerValue', False))

        if is_critical:
            self.check_result = CheckState.CRITICAL
            self.check_message = kwargs.get('messageCritical', message)
        elif is_warning:
            self.check_result = CheckState.WARNING
            self.check_message = kwargs.get('messageWarning', message)
        else:
            self.check_message = message

    def scale_value(self, value):
        if self.options.unit in self.UNIT_SCALE:
            return value / self.UNIT_SCALE[self.options.unit]
        else:
            assert('wrong unit')

    def threshold_warning(self, name: str):
        return self.options.threshold_warning.get(name, self.options.threshold_warning.get(None, None))

    def threshold_critical(self, name: str):
        return self.options.threshold_critical.get(name, self.options.threshold_critical.get(None, None))

    def get_value(self, value, total=None):
        value = float(value)

        if total:
            value /= float(total) / 100
        else:
            value = self.scale_value(value)

        return round(value, 2)

    def add_perfdata(self, name, value, **kwargs):
        unit = kwargs.get('unit', '%')

        perfdata = '{}={}{}'.format(name, value, unit)

        threshold_warning = self.threshold_warning(name)
        threshold_critical = self.threshold_critical(name)

        perfdata += ';'
        if threshold_warning:
            perfdata += str(threshold_warning.value)

        perfdata += ';'
        if threshold_critical:
            perfdata += str(threshold_critical.value)

        perfdata += ';{}'.format(kwargs.get('min', 0))
        perfdata += ';{}'.format(kwargs.get('max', ''))

        self.perfdata.append(perfdata)

    def get_perfdata(self):
        perfdata = ''

        if len(self.perfdata):
            perfdata = '|'
            perfdata += ' '.join(self.perfdata)

        return perfdata

    def check(self):
        self.check_result = CheckState.OK

        if self.options.mode == 'cluster':
            self.check_cluster_status()
        elif self.options.mode == 'version':
            self.check_version()
        elif self.options.mode == 'memory':
            self.check_memory()
        elif self.options.mode == 'swap':
            self.check_swap()
        elif self.options.mode == 'io_wait':
            self.check_io_wait()
        elif self.options.mode == 'disk-health':
            self.check_disks()
        elif self.options.mode == 'cpu':
            self.check_cpu()
        elif self.options.mode == 'services':
            self.check_services()
        elif self.options.mode == 'updates':
            self.check_updates()
        elif self.options.mode == 'subscription':
            self.check_subscription()
        elif self.options.mode == 'storage':
            self.check_storage(self.options.name)
        elif self.options.mode in ['vm', 'vm_status']:
            only_status = self.options.mode == 'vm_status'

            if self.options.name:
                idx = self.options.name
            else:
                idx = self.options.vmid

            if self.options.expected_vm_status:
                self.check_vm_status(idx, expected_state=self.options.expected_vm_status, only_status=only_status)
            else:
                self.check_vm_status(idx, only_status=only_status)
        elif self.options.mode == 'replication':
            self.check_replication()
        elif self.options.mode == 'ceph-health':
            self.check_ceph_health()
        elif self.options.mode == 'zfs-health':
            self.check_zfs_health(self.options.name)
        elif self.options.mode == 'zfs-fragmentation':
            self.check_zfs_fragmentation(self.options.name)
        else:
            message = "Check mode '{}' not known".format(self.options.mode)
            self.output(CheckState.UNKNOWN, message)

        self.check_output()

    def parse_args(self):
        p = argparse.ArgumentParser(description='Check command for PVE hosts via API')

        api_opts = p.add_argument_group('API Options')

        api_opts.add_argument("-e", "--api-endpoint", required=True, help="PVE api endpoint hostname")
        api_opts.add_argument("--api-port", required=False, help="PVE api endpoint port")

        api_opts.add_argument("-u", "--username", dest='api_user', required=True,
                              help="PVE api user (e.g. icinga2@pve or icinga2@pam, depending on which backend you "
                                   "have chosen in proxmox)")

        group = api_opts.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--password", dest='api_password', help="PVE API user password")
        group.add_argument("-t", "--api-token", dest="api_token", help="PVE API token (format: TOKEN_ID=TOKEN_SECRET")

        api_opts.add_argument("-k", "--insecure", dest='api_insecure', action='store_true', default=False,
                              help="Don't verify HTTPS certificate")

        api_opts.set_defaults(api_port=8006)

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=(
                                    'cluster', 'version', 'cpu', 'memory', 'swap', 'storage', 'io_wait', 'updates', 'services',
                                    'subscription', 'vm', 'vm_status', 'replication', 'disk-health', 'ceph-health',
                                    'zfs-health', 'zfs-fragmentation'),
                                required=True,
                                help="Mode to use.")

        check_opts.add_argument('-n', '--node', dest='node',
                                help='Node to check (necessary for all modes except cluster and version)')

        check_opts.add_argument('--name', dest='name',
                                help='Name of storage, vm, or container')

        check_opts.add_argument('--vmid', dest='vmid', type=int,
                                help='ID of virtual machine or container')

        check_opts.add_argument('--expected-vm-status', choices=('running', 'stopped', 'paused'),
                                help='Expected VM status')

        check_opts.add_argument('--ignore-vm-status', dest='ignore_vm_status', action='store_true',
                                help='Ignore VM status in checks',
                                default=False)

        check_opts.add_argument('--ignore-service', dest='ignore_services', action='append', metavar='NAME',
                                help='Ignore service NAME in checks', default=[])

        check_opts.add_argument('--ignore-disk', dest='ignore_disks', action='append', metavar='NAME',
                                help='Ignore disk NAME in health check', default=[])

        check_opts.add_argument('-w', '--warning', dest='threshold_warning', type=CheckThreshold.threshold_type,
                                default={}, help='Warning threshold for check value. Mutiple thresholds with name:value,name:value')
        check_opts.add_argument('-c', '--critical', dest='threshold_critical', type=CheckThreshold.threshold_type,
                                default={}, help='Critical threshold for check value. Mutiple thresholds with name:value,name:value')
        check_opts.add_argument('-M', dest='values_mb', action='store_true', default=False,
                                help='Values are shown in the unit which is set with --unit (if available). Thresholds are also treated in this unit')
        check_opts.add_argument('-V', '--min-version', dest='min_version', type=str,
                                help='The minimal pve version to check for. Any version lower than this will return '
                                     'CRITICAL.')

        check_opts.add_argument('--unit', choices=self.UNIT_SCALE.keys(), default='MiB', help='Unit which is used for performance data and other values')

        options = p.parse_args()

        if not options.node and options.mode not in ['cluster', 'vm', 'vm_status', 'version', 'ceph-health']:
            p.print_usage()
            message = "{}: error: --mode {} requires node name (--node)".format(p.prog, options.mode)
            self.output(CheckState.UNKNOWN, message)

        if not options.vmid and not options.name and options.mode in ('vm', 'vm_status'):
            p.print_usage()
            message = "{}: error: --mode {} requires either vm name (--name) or id (--vmid)".format(p.prog,
                                                                                                    options.mode)
            self.output(CheckState.UNKNOWN, message)

        if not options.name and options.mode == 'storage':
            p.print_usage()
            message = "{}: error: --mode {} requires storage name (--name)".format(p.prog, options.mode)
            self.output(CheckState.UNKNOWN, message)

        def compare_thresholds(threshold_warning, threshold_critical, comparator):
            ok = True
            keys = set(list(threshold_warning.keys()) + list(threshold_critical.keys()))
            for key in keys:
                if (key in threshold_warning and key in threshold_critical) or (None in threshold_warning and None in threshold_critical):
                    ok = ok and comparator(threshold_warning[key], threshold_critical[key])
                elif key in threshold_warning and None in threshold_critical:
                    ok = ok and comparator(threshold_warning[key], threshold_critical[None])
                elif key in threshold_critical and None in threshold_warning:
                    ok = ok and comparator(threshold_warning[None], threshold_critical[key])

            return ok

        if options.threshold_warning and options.threshold_critical:
            if options.mode != 'subscription' and not compare_thresholds(options.threshold_warning, options.threshold_critical, lambda w,c: w<=c):
                p.error("Critical value must be greater than warning value")
            elif options.mode == 'subscription' and not compare_thresholds(options.threshold_warning, options.threshold_critical, lambda w,c: w>=c):
                p.error("Critical value must be lower than warning value")

        self.options = options

    def __init__(self):
        self.options = {}
        self.ticket = None
        self.perfdata = []
        self.check_result = CheckState.UNKNOWN
        self.check_message = ""

        self.__headers = {}
        self.__cookies = {}

        self.parse_args()

        if self.options.api_insecure:
            # disable urllib3 warning about insecure requests
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        if self.options.api_password is not None:
            self.__cookies['PVEAuthCookie'] = self.get_ticket()
        elif self.options.api_token is not None:
            self.__headers["Authorization"] = "PVEAPIToken={}!{}".format(self.options.api_user, self.options.api_token)

pve = CheckPVE()
pve.check()
