# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types as etypes
from ryu.lib.packet import ipv4
from ipaddress import ip_network, ip_address

# TODO: this is a hard copy of info in scenario.py. Gotta change that.
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
            'mac': '70:88:99:00:00:01',
            'ip': '10.0.0.1/24'
        }, {
            'mac': '70:88:99:10:00:02',
            'ip': '10.0.1.1/24'
        }],
}

# This app supports ONE router.
class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # This routing doesn't support next hop, just output interface.
        # I'm making a distinction between 'interfaces' data from INTERFACES
        # and 'ports' data from the datapath
        self.routes = [
            {'net': ip_network(iface['ip'], strict=False),
             'out_iface': n}
            for n, iface in enumerate(INTERFACES['s1'])
        ]
        self.arpDict = {
            iface['ip'].split('/')[0]: iface['mac']
            for dev in INTERFACES.values() for iface in dev
        }

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip  = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype in [ etypes.ETH_TYPE_LLDP, etypes.ETH_TYPE_IPV6 ]:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        out_port = None
        actions = []
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        elif ip:
            self.logger.info(f' IPv4 {ip.src} to {ip.dst} {ip.ttl}')
            actions = self.ip_in_handler(datapath, ip)

        # Fallback
        if not actions:
            if not out_port:
                self.logger.info(' no match, flooding')
                out_port = ofproto.OFPP_FLOOD
            actions += [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def ip_in_handler(self, datapath, ip):
        ip_dest = ip_address(ip.dst)

        out_port = None
        for rule in self.routes:
            if ip_dest in rule['net']:
                if 'out_port' not in rule:
                    # Map an 'interface' as defined in INTERFACES to a real port
                    out_mac = INTERFACES['s1'][rule['out_iface']]['mac']
                    rule['out_port'] = next((
                        port_n for port_n, port in datapath.ports.items()
                        if port.hw_addr == out_mac and port.config != 1
                    ))
                out_port = rule['out_port']

        if not out_port:  return None

        self.logger.info(f'  route match to output port {out_port}')
        return self.actionsForward(
            datapath, out_port,
            datapath.ports[out_port].hw_addr, self.arpDict[ip.dst]
        )

    def actionsForward(self, datapath, port, src, dst):
        parser = datapath.ofproto_parser
        return [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src),
            parser.OFPActionSetField(eth_dst=dst),
            parser.OFPActionOutput(port)
        ]
