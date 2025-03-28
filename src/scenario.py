#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
# from mininet.topo import SingleSwitchTopo
from mininet.node import Host
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from functools import partial
# from sys import argv

INTERFACES = {
    'h1': [{
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.2'
        }],
    'h2': [{
            'mac': '00:00:00:00:00:02',
            'ip': '10.0.1.2'
        }],
    's1': [{
            'mac': '70:88:99:10:00:01',
            'ip': '10.0.0.1'
        }, {
            'mac': '70:88:99:10:00:02',
            'ip': '10.0.1.1'
        }],
}

ARP_DICT = {i['ip']: i['mac'] for dev in INTERFACES.values() for i in dev}
ARP_TUPLES = ((i['ip'], i['mac']) for dev in INTERFACES.values() for i in dev)

class StarTopo(Topo):
    'A single switch connected to the hosts defined in the constructor.'

    DEFAULT_HOSTS = [{'name': 'h1'}, {'name':'h2'}]

    def build(self, hosts=DEFAULT_HOSTS, autoSetMacs=False, arpTable=None):
        switch = self.addSwitch('s1')
        for n, opts in enumerate(hosts):
            opts['name'] = opts.get('name', f'h{n+1}')
            opts['mac'] = opts.get('mac', int2mac(n+1) if autoSetMacs else None)

            host = self.addHost(**opts)
            self.addLink(host, switch)

class ArpHost(Host):
    "Host that's initialized with an ARP cache"

    def config(self, arpTable={}, **params):
        r = super().config(**params)
        for ip, mac in arpTable:  self.setARP(ip, mac)
        return r


def int2mac(mac_int: int):
    hex_str = f'{mac_int:012x}'
    return ':'.join(hex_str[i:i+2] for i in range(0,12,2))


def simpleTestCLI(arpTable=None):

    hostOpts = [
        { 'mac': INTERFACES['h1'][0]['mac'] },
        { 'mac': INTERFACES['h2'][0]['mac'] }
    ]

    net = Mininet(
            host       = partial(ArpHost, arp=arpTable),
            topo       = StarTopo(hostOpts, arpTable=arpTable),
            controller = partial(RemoteController, ip='127.0.0.1'),
            switch     = partial(OVSSwitch, protocols='OpenFlow13')
        )
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':

    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTestCLI(arpTable=ARP_DICT)
