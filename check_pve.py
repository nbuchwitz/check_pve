#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_pve.py - A check plugin for Proxmox Virtual Environment (PVE).
# Copyright (C) 2018  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 1.1.2
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

from __future__ import print_function
import sys

try:
    from enum import Enum
    from datetime import datetime
    import argparse
    import requests
    import urllib3

    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)

try:
    dict.iteritems
except AttributeError:
    # Python 3
    def iteritems(d):
        return iter(d.items())
else:
    # Python 2
    def iteritems(d):
        return d.iteritems()


class NagiosState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckPVE:
    VERSION = '1.1.2'
    API_URL = 'https://{}:8006/api2/json/{}'

    options = {}
    ticket = None
    perfdata = []
    checkResult = -1
    checkMessage = ""

    def checkOutput(self):
        message = self.checkMessage
        if self.perfdata:
            message += self.getPerfdata()

        self.output(self.checkResult, message)

    def output(self, returnCode, message):
        prefix = returnCode.name

        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(returnCode.value)

    def getURL(self, part):
        return self.API_URL.format(self.options.api_endpoint, part)

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
                    cookies=self.ticket,
                    params=kwargs.get('params', None)
                )
            else:
                self.output(NagiosState.CRITICAL, "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            self.output(NagiosState.UNKNOWN, "Could not connect to PVE API: Connection timeout")
        except requests.exceptions.SSLError:
            self.output(NagiosState.UNKNOWN, "Could not connect to PVE API: Certificate validation failed")
        except requests.exceptions.ConnectionError:
            self.output(NagiosState.UNKNOWN, "Could not connect to PVE API: Failed to resolve hostname")

        if response.ok:
            return response.json()['data']
        else:
            message = "Could not fetch data from API: "

            if response.status_code == 401:
                message += "Could not connection to PVE API: invalid username or password"
            elif response.status_code == 403:
                message += "Access denied. Please check if API user has sufficient permissions."
            else:
                message += "HTTP error code was {}".format(response.status_code)

            self.output(NagiosState.UNKNOWN, message)

    def getTicket(self):
        url = self.getURL('access/ticket')
        data = {"username": self.options.api_user, "password": self.options.api_password}
        result = self.request(url, "post", data=data)

        self.ticket = {'PVEAuthCookie': result['ticket']}

    def checkAPIValue(self, url, message, **kwargs):
        result = self.request(url)
        used = None

        if 'key' in kwargs:
            result = result[kwargs.get('key')]

        if isinstance(result, (dict,)):
            used_percent = self.getValue(result['used'], result['total'])
            used = self.getValue(result['used'])
            total = self.getValue(result['total'])

            self.addPerfdata(kwargs.get('perfkey', 'usage'), used_percent)
            self.addPerfdata(kwargs.get('perfkey', 'used'), used, max=total, unit='MB')
        else:
            used_percent = round(float(result) * 100, 2)
            self.addPerfdata(kwargs.get('perfkey', 'usage'), used_percent)

        if self.options.values_mb:
            message += ' {}{}'.format(used, 'MB')
            value = used
        else:
            message += ' {}{}'.format(used_percent, '%')
            value = used_percent

        self.checkTresholds(value, message)

    def checkVMStatus(self, idx, **kwargs):
        url = self.getURL('cluster/resources', )
        data = self.request(url, params={'type': 'vm'})

        expected_state = kwargs.get("expected_state", "running")
        only_status = kwargs.get("only_status", False)

        found = False
        for vm in data:
            if vm['name'] == idx or vm['vmid'] == idx:
                if vm['status'] != expected_state:
                    self.checkMessage = "VM '{}' is {} (expected: {})".format(vm['name'], vm['status'], expected_state)
                    if not self.options.ignore_vm_status:
                        self.checkResult = NagiosState.CRITICAL
                else:
                    if self.options.node and self.options.node != vm['node']:
                        self.checkMessage = "VM '{}' is {}, but located on node '{}' instead of '{}'" \
                            .format(vm['name'], expected_state, vm['node'], self.options.node)
                        self.checkResult = NagiosState.WARNING
                    else:
                        self.checkMessage = "VM '{}' on node '{}' is {}" \
                            .format(vm['name'], vm['node'], expected_state)

                if vm['status'] == 'running' and not only_status:
                    self.addPerfdata("cpu", round(vm['cpu'] * 100, 2))

                    if self.options.values_mb:
                        memory = vm['mem'] /1024/1024
                        self.addPerfdata("memory", memory, unit="MB", max=vm['maxmem']/1024/1024)

                    else:
                        memory = self.getValue(vm['mem'], vm['maxmem'])
                        self.addPerfdata("memory", memory)

                    self.checkTresholds(memory, message=self.checkMessage)

                found = True
                break

        if not found:
            self.checkMessage = "VM '{}' not found".format(idx)
            self.checkResult = NagiosState.WARNING

    def checkDisks(self):
        url = self.getURL('nodes/{}/disks'.format(self.options.node))

        failed = []
        disks = self.request(url + '/list')
        for disk in disks:
            name = disk['devpath'].replace('/dev/', '')

            if name in self.options.ignore_disks:
                continue

            if disk['health'] not in ('PASSED', 'OK'):
                self.checkResult = NagiosState.WARNING
                failed.append({"serial": disk["serial"], "device": disk['devpath']})

            if disk['wearout'] != 'N/A':
                self.addPerfdata('wearout_{}'.format(name), disk['wearout'])

        if failed:
            self.checkMessage = "The following disks failed the health test:\n"
            for disk in failed:
                self.checkMessage += "  {} with serial '{}'\n".format(disk['device'], disk['serial'])
        else:
            self.checkMessage = "All disks are healthy"

    def checkReplication(self, name):
        url = self.getURL('nodes/{}/replication'.format(self.options.node))

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
            self.checkMessage = message
            self.checkResult = NagiosState.WARNING
        else:
            self.checkMessage = "No failed replication jobs on {}".format(self.options.node)
            self.checkResult = NagiosState.OK

        if len(performance_data) > 0:
            for metric in performance_data:
                self.addPerfdata('duration_' + metric['id'], metric['duration'], unit='s')

    def checkServices(self):
        url = self.getURL('nodes/{}/services'.format(self.options.node))
        data = self.request(url)

        failed = {}
        for service in data:
            if service['state'] != 'running' and service['name'] not in self.options.ignore_services:
                failed[service['name']] = service['desc']

        if failed:
            self.checkResult = NagiosState.CRITICAL
            message = "{} services not running:\n\n".format(len(failed))
            message += "\n".join(['* {}: {}'.format(i, failed[i]) for i in failed])
            self.checkMessage = message
        else:
            self.checkMessage = "All services running"

    def checkSubscription(self):
        url = self.getURL('nodes/{}/subscription'.format(self.options.node))
        data = self.request(url)

        if data['status'] == 'NotFound':
            self.checkResult = NagiosState.WARNING
            self.checkMessage = "No valid subscription found"
        if data['status'] == 'Inactive':
            self.checkResult = NagiosState.CRITICAL
            self.checkMessage = "Subscription expired"
        elif data['status'] == 'Active':
            subscriptionDueDate = data['nextduedate']
            subscriptionProductName = data['productname']

            dateExpire = datetime.strptime(subscriptionDueDate, '%Y-%m-%d')
            dateToday = datetime.today()
            delta = (dateExpire - dateToday).days

            message = '{} is valid until {}'.format(
                subscriptionProductName,
                subscriptionDueDate)
            messageWarningCritical = '{} will expire in {} days ({})'.format(
                subscriptionProductName,
                delta,
                subscriptionDueDate)

            self.checkTresholds(delta, message, messageWarning=messageWarningCritical,
                                messageCritical=messageWarningCritical, lowerValue=True)

    def checkUpdates(self):
        url = self.getURL('nodes/{}/apt/update'.format(self.options.node))
        count = len(self.request(url))

        if count:
            self.checkResult = NagiosState.WARNING
            msg = "{} pending update"
            if count > 1:
                msg += "s"
            self.checkMessage = msg.format(count)
        else:
            self.checkMessage = "System up to date"

    def checkClusterStatus(self):
        url = self.getURL('cluster/status')
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

        if quorate == None:
            self.checkMessage = 'No cluster configuration found'
        elif quorate:
            nodeCount = len(nodes)
            nodesOnlineCount = len({k: v for k, v in iteritems(nodes) if v})

            if nodeCount > nodesOnlineCount:
                diff = nodeCount - nodesOnlineCount
                self.checkResult = NagiosState.WARNING
                self.checkMessage = "Cluster '{}' is healthy, but {} node(s) offline'".format(cluster, diff)
            else:
                self.checkMessage = "Cluster '{}' is healthy'".format(cluster)
        else:
            self.checkResult = NagiosState.CRITICAL
            self.checkMessage = 'Cluster is unhealthy - no quorum'

    def checkStorage(self, name):
        # check if storage exists
        url = self.getURL('nodes/{}/storage'.format(self.options.node))
        data = self.request(url)

        if not any(s['storage'] == name for s in data):
            self.checkResult = NagiosState.CRITICAL
            self.checkMessage = "Storage '{}' doesn't exist on node '{}'".format(name, self.options.node)
            return

        url = self.getURL('nodes/{}/storage/{}/status'.format(self.options.node, name))
        self.checkAPIValue(url, 'Storage usage is')

    def checkMemory(self):
        url = self.getURL('nodes/{}/status'.format(self.options.node))
        self.checkAPIValue(url, 'Memory usage is', key='memory')

    def checkCPU(self):
        url = self.getURL('nodes/{}/status'.format(self.options.node))
        self.checkAPIValue(url, 'CPU usage is', key='cpu')

    def checkIOWait(self):
        url = self.getURL('nodes/{}/status'.format(self.options.node))
        self.checkAPIValue(url, 'IO wait is', key='wait', perfkey='wait')

    def checkTresholds(self, value, message, **kwargs):
        isWarning = False
        isCritical = False

        if kwargs.get('lowerValue', False):
            isWarning = self.options.treshold_warning and value < float(self.options.treshold_warning)
            isCritical = self.options.treshold_critical and value < float(self.options.treshold_critical)
        else:
            isWarning = self.options.treshold_warning and value > float(self.options.treshold_warning)
            isCritical = self.options.treshold_critical and value > float(self.options.treshold_critical)

        if isCritical:
            self.checkResult = NagiosState.CRITICAL
            self.checkMessage = kwargs.get('messageCritical', message)
        elif isWarning:
            self.checkResult = NagiosState.WARNING
            self.checkMessage = kwargs.get('messageWarning', message)
        else:
            self.checkResult = NagiosState.OK
            self.checkMessage = message

    def getValue(self, value, total=None):
        value = float(value)

        if total:
            value /= float(total) / 100
        else:
            value /= 1024 * 1024

        return round(value, 2)

    def addPerfdata(self, name, value, **kwargs):
        unit = kwargs.get('unit', '%')

        perfdata = '{}={}{}'.format(name, value, unit)

        if self.options.treshold_warning and (self.options.values_mb == (unit == 'MB')):
            perfdata += ';{}'.format(self.options.treshold_warning)
        else:
            perfdata += ';'

        if self.options.treshold_critical and (self.options.values_mb == (unit == 'MB')):
            perfdata += ';{}'.format(self.options.treshold_critical)
        else:
            perfdata += ';'

        if ('max' in kwargs):
            perfdata += ';{}'.format(kwargs.get('max'))

        self.perfdata.append(perfdata)

    def getPerfdata(self):
        perfdata = ''

        if (len(self.perfdata) > 0):
            perfdata = '|'
            perfdata += ' '.join(self.perfdata)

        return perfdata

    def check(self):
        self.checkResult = NagiosState.OK

        if self.options.mode == 'cluster':
            self.checkClusterStatus()
        else:
            if self.options.mode == 'memory':
                self.checkMemory()
            elif self.options.mode == 'io_wait':
                self.checkIOWait()
            elif self.options.mode == 'disk-health':
                self.checkDisks()
            elif self.options.mode == 'cpu':
                self.checkCPU()
            elif self.options.mode == 'services':
                self.checkServices()
            elif self.options.mode == 'updates':
                self.checkUpdates()
            elif self.options.mode == 'subscription':
                self.checkSubscription()
            elif self.options.mode == 'storage':
                self.checkStorage(self.options.name)
            elif self.options.mode in ['vm', 'vm_status']:
                only_status = self.options.mode == 'vm_status'

                if self.options.name:
                    idx = self.options.name
                else:
                    idx = self.options.vmid

                if self.options.expected_vm_status:
                    self.checkVMStatus(idx, expected_state=self.options.expected_vm_status, only_status=only_status)
                else:
                    self.checkVMStatus(idx, only_status=only_status)
            elif self.options.mode == 'replication':
                self.checkReplication(self.options.name)
            else:
                message = "Check mode '{}' not known".format(self.options.mode)
                self.output(NagiosState.UNKNOWN, message)

        self.checkOutput()

    def parseOptions(self):
        p = argparse.ArgumentParser(description='Check command for PVE hosts via API')

        api_opts = p.add_argument_group('API Options')

        api_opts.add_argument("-e", "--api-endpoint", required=True, help="PVE api endpoint hostname")
        api_opts.add_argument("-u", "--username", dest='api_user', required=True,
                              help="PVE api user (e.g. icinga2@pve or icinga2@pam, depending on which backend you have chosen in proxmox)")
        api_opts.add_argument("-p", "--password", dest='api_password', required=True, help="PVE api user password")
        api_opts.add_argument("-k", "--insecure", dest='api_insecure', action='store_true', default=False,
                              help="Don't verify HTTPS certificate")

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=('cluster', 'cpu', 'memory', 'storage', 'io_wait', 'updates', 'services',
                                         'subscription', 'vm','vm_status', 'replication', 'disk-health'),
                                required=True,
                                help="Mode to use.")

        check_opts.add_argument('-n', '--node', dest='node',
                                help='Node to check (necessary for all modes except cluster)')

        check_opts.add_argument('--name', dest='name',
                                help='Name of storage or vm')

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

        check_opts.add_argument('-w', '--warning', dest='treshold_warning', type=float,
                                help='Warning treshold for check value')
        check_opts.add_argument('-c', '--critical', dest='treshold_critical', type=float,
                                help='Critical treshold for check value')
        check_opts.add_argument('-M', dest='values_mb', action='store_true', default=False,
                                help='Values are shown in MB (if available). Tresholds are also treated as MB values')

        options = p.parse_args()

        if not options.node and options.mode not in ['cluster', 'vm']:
            p.print_usage()
            message = "{}: error: --mode {} requires node name (--node)".format(p.prog, options.mode)
            self.output(NagiosState.UNKNOWN, message)

        if not options.vmid and not options.name and options.mode == 'vm':
            p.print_usage()
            message = "{}: error: --mode {} requires either vm name (--name) or id (--vmid)".format(p.prog,
                                                                                                    options.mode)
            self.output(NagiosState.UNKNOWN, message)

        if not options.name and options.mode == 'storage':
            p.print_usage()
            message = "{}: error: --mode {} requires storage name (--name)".format(p.prog, options.mode)
            self.output(NagiosState.UNKNOWN, message)

        if options.treshold_warning and options.treshold_critical:
            if options.mode != 'subscription' and options.treshold_critical <= options.treshold_warning:
                p.error("Critical value must be greater than warning value")
            elif options.mode == 'subscription' and options.treshold_critical >= options.treshold_warning:
                p.error("Critical value must be lower than warning value")

        self.options = options

    def __init__(self):
        self.parseOptions()
        self.getTicket()


pve = CheckPVE()
pve.check()
