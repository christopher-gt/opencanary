from opencanary.modules import CanaryService
from opencanary.modules import FileSystemWatcher
import os
import re

arp_re = re.compile('(?P<type>[a-z ]*)\s+(?P<ip>([0-9]{1,3}\.){3}([0-9]{1,3}))\s+(?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})\s+(?P<interface>\S+)')

class ArpLogWatcher(FileSystemWatcher):
    def __init__(self, logger=None, logFile=None):
        self.logger = logger
        FileSystemWatcher.__init__(self, filename=logFile)

    def handleLines(self, lines=[]):
        for line in lines:
            try:
                (rubbish, log) = line.split('arpwatch: ')
            except ValueError:
                continue

            m = arp_re.match(log)
            if not m:
                continue

            data = {'logdata': {'TYPE': 'arpwatch %s' % m.group('type'),
                                'IP': m.group('ip'),
                                'MAC': m.group('mac'),
                                'INTERFACE': m.group('interface')}}

            self.logger.log(data)

class CanaryArpwatch(CanaryService):
    NAME = 'arpwatch'

    def __init__(self.config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.audit_file = config.getVal('arpwatch.logfile', default='/var/log/arpwatch.log')
        self.config = config

    def startYourEngines(self, reactor=None):
        fs = ArpLogWatcher(logFile=self.audit_file, logger=self.logger)
        fs.start()

    def configUpdated(self,):
        pass

            
                 
