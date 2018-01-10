#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from datetime import datetime
import argparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CheckPVE:
    VERSION = '1.0.0'
    API_URL = 'https://{}:8006/api2/json/{}'

    RESULT_OK = 0
    RESULT_WARNING = 1
    RESULT_CRITICAL = 2
    RESULT_UNKNOWN = 3

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
        prefix = ''

        if returnCode == self.RESULT_OK:
            prefix = 'OK'
        elif returnCode == self.RESULT_WARNING:
            prefix = 'WARNING'
        elif returnCode == self.RESULT_CRITICAL:
            prefix = 'CRITICAL'
        elif returnCode == self.RESULT_UNKNOWN:
            prefix = 'UNKNOWN'

        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(returnCode)

    def getURL(self, part):
        return self.API_URL.format(self.options.api_endpoint, part)

    def request(self, url, method='get', **kwargs):
        try:
            if method == 'post':
                response = requests.post(url, verify=not self.options.api_insecure, data=kwargs.get('data', None),
                                         timeout=5)
            elif method == 'get':
                response = requests.get(url, verify=not self.options.api_insecure, cookies=self.ticket)
            else:
                self.output(self.RESULT_CRITICAL, "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            self.output(self.RESULT_UNKNOWN, "Could not connect to PVE API: Connection timeout")
        except requests.exceptions.ConnectionError:
            self.output(self.RESULT_UNKNOWN, "Could not connect to PVE API: Failed to resolve hostname")
        except requests.exceptions.SSLError:
            self.output(self.RESULT_UNKNOWN, "Could not connect to PVE API: Certificate validation failed")

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

            self.output(self.RESULT_UNKNOWN, message)

    def getTicket(self):
        url = self.getURL('access/ticket')
        data = {"username": self.options.api_user, "password": self.options.api_password}
        result = self.request(url, "post", data=data)

        self.ticket = {'PVEAuthCookie': result['ticket']}

    def checkAPIValue(self, url, message, **kwargs):
        result = self.request(url)

        if kwargs.has_key('key'):
            result = result[kwargs.get('key')]

        if self.getUnit() == '%':
            total = 100

            if isinstance(result, (dict,)):
                used = self.getValue(result['used'], result['total'])
            else:
                used = self.getValue(float(result) * 100)
        else:
            total = self.getValue(result['total'])
            used = self.getValue(result['used'])

        message += ' {}{}'.format(used, self.getUnit())
        self.checkTresholds(used, message)

        self.addPerfdata(kwargs.get('perfkey', 'usage'), used, total)

    def checkSubscription(self):
        url = self.getURL('nodes/{}/subscription'.format(self.options.node))
        data = self.request(url)

        if data['status'] == 'NotFound':
            self.checkResult = self.RESULT_WARNING
            self.checkMessage = "No valid subscription found"
        if data['status'] == 'Inactive':
            self.checkResult = self.RESULT_CRITICAL
            self.checkMessage = "Subscription expired"
        elif data['status'] == 'Active':
            subscriptionDueDate = data['nextduedate']
            subscriptionLevel = data['level']

            dateExpire = datetime.strptime(subscriptionDueDate, '%Y-%m-%d')
            dateToday = datetime.today()
            delta = (dateExpire - dateToday).days

            subscriptionLevels = {'c': 'Community', 'b': 'Basic', 's': 'Standard', 'p': 'Premium'}

            message = 'Subscription of level \'{}\' is valid until {}'.format(
                subscriptionLevels[subscriptionLevel],
                subscriptionDueDate)
            messageWarningCritical = 'Subscription of level \'{}\' will expire in {} days ({})'.format(
                subscriptionLevel,
                delta,
                subscriptionDueDate)

            self.checkTresholds(delta, message, messageWarning=messageWarningCritical,
                                messageCritical=messageWarningCritical, lowerValue=True)

    def checkUpdates(self):
        url = self.getURL('nodes/{}/apt/update'.format(self.options.node))
        count = len(self.request(url))
        if (count):
            self.checkResult = self.RESULT_WARNING
            self.checkMessage = "{} pending updates".format(count)
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

        if not quorate:
            self.checkMessage = 'No cluster configuration found'
        elif quorate:
            nodeCount = len(nodes)
            nodesOnlineCount = len({k: v for k, v in nodes.iteritems() if v})

            if nodeCount > nodesOnlineCount:
                diff = nodeCount - nodesOnlineCount
                self.checkResult = self.RESULT_WARNING
                self.checkMessage = "Cluster '{}' is healthy, but {} node(s) offline'".format(cluster, diff)
            else:
                self.checkMessage = "Cluster '{}' is healthy'".format(cluster)
        else:
            self.checkResult = self.RESULT_CRITICAL
            self.checkMessage = 'Cluster is unhealthy - no quorum'

    def checkStorageStatus(self, name):
        url = self.getURL('nodes/{}/storage/{}/status'.format(self.options.node, name))
        self.checkAPIValue(url, 'Storage usage is')

    def checkMemory(self):
        url = self.getURL('nodes/{}/status'.format(self.options.node))
        self.checkAPIValue(url, 'Memory usage is', key='memory')

    def checkCPU(self):
        self.options.unit = '%'
        url = self.getURL('nodes/{}/status'.format(self.options.node))
        self.checkAPIValue(url, 'CPU usage is', key='cpu')

    def checkIOWait(self):
        self.options.unit = '%'
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
            self.checkResult = self.RESULT_CRITICAL
            self.checkMessage = kwargs.get('messageCritical', message)
        elif isWarning:
            self.checkResult = self.RESULT_WARNING
            self.checkMessage = kwargs.get('messageWarning', message)
        else:
            self.checkResult = self.RESULT_OK
            self.checkMessage = message

    def getValue(self, value, total=None):
        if total:
            value = self.getPercentValue(value, total)
        else:
            value = self.transformValue(value)

        return round(value, 2)

    def getPercentValue(self, used, total):
        return float(used) / float(total) * 100

    def transformValue(self, value):
        value = float(value)
        unit = self.getUnit()

        if unit == 'GB':
            value /= 1024 * 1024 * 1024
        elif unit == 'MB':
            value /= 1024 * 1024

        return value

    def getUnit(self):
        return self.options.unit

    def addPerfdata(self, name, value, max=None, min=None):
        unit = self.getUnit()

        if unit == '%':
            max = '100'

        perfdata = '{}={}{}'.format(name, value, unit)

        if self.options.treshold_warning:
            perfdata += ';{}{}'.format(self.options.treshold_warning, unit)
        else:
            perfdata += ';'

        if self.options.treshold_critical:
            perfdata += ';{}{}'.format(self.options.treshold_critical, unit)
        else:
            perfdata += ';'

        if (max):
            perfdata += ';{}{}'.format(max, unit)

        self.perfdata.append(perfdata)

    def getPerfdata(self):
        perfdata = ''

        if (len(self.perfdata) > 0):
            perfdata = '|'
            perfdata += ' '.join(self.perfdata)

        return perfdata

    def check(self):
        self.checkResult = self.RESULT_OK

        if self.options.mode == 'cluster':
            self.checkClusterStatus()
        else:
            if self.options.mode == 'memory':
                self.checkMemory()
            elif self.options.mode == 'io_wait':
                self.checkCPU()
            elif self.options.mode == 'cpu':
                self.checkCPU()
            elif self.options.mode == 'storage':
                if not self.options.storage:
                    self.output(self.RESULT_UNKNOWN, "Missing the name of  the storage")
                self.checkStorageStatus(self.options.storage)
            elif self.options.mode == 'updates':
                self.checkUpdates()
            elif self.options.mode == 'subscription':
                self.checkSubscription()

        self.checkOutput()

    def parseOptions(self):
        p = argparse.ArgumentParser(description='Check command for PVE hosts via API')

        api_opts = p.add_argument_group('API Options')

        api_opts.add_argument("-e", "--api-endpoint", required=True, help="PVE api endpoint hostname")
        api_opts.add_argument("-u", "--username", dest='api_user', required=True, help="PVE api user")
        api_opts.add_argument("-p", "--password", dest='api_password', required=True, help="PVE api user password")
        api_opts.add_argument("-k", "--insecure", dest='api_insecure', action='store_true', default=False,
                              help="Don't verify HTTPS certificate")

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=('cluster', 'cpu', 'memory', 'storage', 'io_wait', 'updates', 'subscription'),
                                required=True,
                                help="Mode to use.")

        check_opts.add_argument('-n', '--node', dest='node',
                                help='Node to check (necessary for all modes except cluster)')

        check_opts.add_argument('-s', '--storage', dest='storage',
                                help='Name of storage')

        check_opts.add_argument('-w', '--warning', dest='treshold_warning', help='Warning treshold for check value')
        check_opts.add_argument('-c', '--critical', dest='treshold_critical', help='Critical treshold for check value')

        check_opts.add_argument('-U', '--unit', dest='unit', choices=('GB', 'MB', '%'),
                                default='GB', help='Return numerical values in GB, MB or %%')

        options = p.parse_args()

        if not options.node and options.mode != 'cluster':
            print "Missing node name for check '{}'".format(options.mode)
            p.print_usage()
            sys.exit(self.RESULT_UNKNOWN)

        if options.treshold_warning and options.treshold_critical and options.treshold_critical <= options.treshold_warning:
            p.error("Critical value must be greater than warning value")

        self.options = options

        pass

    def __init__(self):
        self.parseOptions()
        self.getTicket()


pve = CheckPVE()
pve.check()
