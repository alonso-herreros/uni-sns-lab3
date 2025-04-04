#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Host
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from functools import partial

# Define all interfaces once and only once
INTERFACES = {
    'h1': [{
            'mac': '00:00:00:00:00:01',
            'ip': '10.0.0.2/24'
        }],
    'h2': [{
            'mac': '00:00:00:00:00:02',
            'ip': '10.0.1.2/24'
        }],
    's1': [{
            'mac': '70:88:99:10:00:01',
            'ip': '10.0.0.1/24'
        }, {
            'mac': '70:88:99:10:00:02',
            'ip': '10.0.1.1/24'
        }],
}

# Define each host through its (hopefully) only interface
HOSTS = [ ifaces[0] for hname, ifaces in INTERFACES.items() if hname[0]=='h' ]

# From the interfaces, define the ARP table
# ARP_DICT = {i['ip']: i['mac'] for dev in INTERFACES.values() for i in dev}
ARP_ENTRIES = [
        (dev['ip'].split('/')[0], dev['mac']) # IP address before the '/'
        for node in INTERFACES.values() for dev in node
    ]


class StarTopo(Topo):
    """
    A single switch connected to the defined hosts
    """

    DEFAULT_HOSTS = [{}, {}] # Defaults to two hosts with default config

    def build(self, hosts=DEFAULT_HOSTS, autoSetMacs=False):
        switch = self.addSwitch('s1')
        for n, opts in enumerate(hosts):
            opts['name'] = opts.get('name', f'h{n+1}')
            opts['mac'] = opts.get('mac', int2mac(n+1) if autoSetMacs else None)

            host = self.addHost(**opts)
            self.addLink(host, switch)

class ArpHost(Host):
    "Host that's initialized with an ARP cache"

    def config(self, arpEntries={}, **params):
        r = super().config(**params)
        for ip, mac in arpEntries:  self.setARP(ip, mac)
        return r


def int2mac(mac_int: int):
    hex_str = f'{mac_int:012x}'
    return ':'.join(hex_str[i:i+2] for i in range(0,12,2))


def simpleTestCLI():

    net = Mininet(
            topo       = StarTopo(HOSTS),
            host       = partial(ArpHost, arpEntries=ARP_ENTRIES),
            controller = partial(RemoteController, ip='127.0.0.1'),
            switch     = partial(OVSSwitch, protocols='OpenFlow13')
        )
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':

    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTestCLI()
