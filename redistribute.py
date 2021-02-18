from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu import utils

from ryu.lib.packet import arp,bgp,bpdu,dhcp,ethernet,icmp,icmpv6,igmp,ipv4,ipv6,llc,lldp,mpls,ospf,pbb,sctp,slow,tcp,udp,vlan,vrrp

from collections import deque
from collections import defaultdict

from ryu.lib import hub
import igraph, ast, random

from threading import Thread
from time import sleep

from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link
import copy


class toposomething(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Handy function that lists all attributes in the given object
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def __init__(self, *args, **kwargs):
        super(toposomething, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.graph = igraph.Graph(directed=True)
        self.hosts_to_switch = {}
        self.comm_list={}

        # configure testing parameters
        with open('param_config') as f:
            for line in f:
                try:
                    config = ast.literal_eval(line)
                except:
                    continue

                self.T1 = config["T1"]
                self.T2 = config["T2"]
                self.S1 = config["S1"]
                self.strategy = config["strategy"]
                self.monitoring_on = config["monitoring_on"]
                self.redistribute_on = config["redistribute_on"]
                self.flow_logging_on = config["flow_logging_on"]
                self.port_logging_on = config["port_logging_on"]

        if self.strategy != 'proactive':
            self.redistribute_on = False
        else:
            self.monitoring_on = True

        #print 'monitoring every', self.T1, 'seconds'
        #print 'redistributing every', self.T2, 'seconds'
        #print 'keeping track of the last', self.S1, 'bandwidths'

        # configure link parameters
        self.link_config = {}
        with open('link_config') as f:
            for line in f:
                try:
                    config = ast.literal_eval(line)
                except:
                    continue
                self.link_config.setdefault(config["input_port"], {})
                self.link_config[config["input_port"]][config["output_port"]] = {"bw": config["bandwidth"], "lat": config["latency"]}

        self.BYTES_PER_MEGABIT = 125000

        if self.monitoring_on:
            self.monitor_thread = hub.spawn(self._monitor)

        # spawn a redistribution thread
        self.redistributing = False
        if self.redistribute_on:
            self.redist_thread = Thread(target=self.redistribute_thread)
            self.redist_thread.start()

        #print 'we are using a', self.strategy, 'strategy with redistribute_on:', self.redistribute_on
        #print 'with params T1:', self.T1, 'seconds T2:', self.T2, 'seconds S1:', self.S1, 'items'
        #print 'monitoring_on:', self.monitoring_on, 'flow_logging_on:', self.flow_logging_on, 'port_logging_on', self.port_logging_on


    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # We are not using this function
    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.hosts_to_switch:
            #print 'deleting flows for dst:', dst, ' on datapath:', datapath.id
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 0, 1, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            self.mac_to_port[dpid][src_mac] = in_port
            if src_mac not in self.hosts_to_switch:
                self.hosts_to_switch[src_mac] = dpid
                self.comm_list.setdefault(src_mac, {})
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if self.redistributing:
            # just drop all packet in events while we are redistributing
            return

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6)
            self.add_flow(datapath, 0, 1, match, actions)
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return

            pi = not (str(eth.dst) == '01:80:c2:00:00:0e')
            packet_in_rcvd = ("\t\tpacket in s%s %s %s %s" % (dpid, eth.src, eth.dst, in_port))
            if pi: print(packet_in_rcvd)

            out_port = None
            if eth.dst in self.hosts_to_switch:

                dst_switch_dpid = self.hosts_to_switch[eth.dst]
                dst_switch_vid = self.graph.vs.find(name=str(dst_switch_dpid)).index
                start_switch_vid = self.graph.vs.find(name=str(dpid)).index

                #print 'finding path from', dpid, 'to', dst_switch_dpid

                if self.strategy == "shortest_path":
                    #print 'finding shortest_path'
                    path = self.graph.get_shortest_paths(str(dpid), str(dst_switch_dpid), output='epath')[0]
                elif self.strategy == "widest_path":
                    path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw')
                elif self.strategy == "proactive":
                    path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='estimated_bw')
                    #print 'using proactive rules. found path of bw: ', path_bw
                    if path_bw <= 0:
                        #print 'effective bandwidth zero, reverting to original rules'
                        path, path_bw = self.widest_path(start_switch_vid, dst_switch_vid, bw='bw')
                else:
                    #print 'invalid strategy parameters'
                    exit()

                if len(path) != 0:
                    #print 'found path:',
                    for p in path:
                        #print self.graph.es[p]['src_dpid'],
                    #print 'fin'
                    out_port = self.graph.es[path[0]]['src_port']
                else:
                    #print 'same switch'
                    out_port = mac_to_port_table[eth.dst]

                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst, in_port=in_port,
                                        eth_type=eth.ethertype)
                #print '\t\t\tadding flow on s', dpid, 'in:', in_port, 'out:', out_port, 'dst:', eth.dst
                self.add_flow(datapath, 0, 1, match, actions)
                self.send_packet_out(datapath, msg.buffer_id, in_port,
                                     out_port, msg.data)
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    #print "IPV4 packet enter in different ports"
                    return
                else:
                    #print 'flooding'
                    self.flood(msg)

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        #print "Switch %d entered" % ev.switch.dp.id
        self.graph.add_vertex(str(ev.switch.dp.id))

    @set_ev_cls(event.EventSwitchLeave)
    def handler_switch_leave(self, ev):
        #print "Switch left"
        self.graph.delete_vertices(str(ev.switch.dp.id))

    @set_ev_cls(event.EventLinkAdd)
    def handler_link_add(self, ev):
        #print ev.link.src.dpid, ev.link.src.port_no, ev.link.dst.dpid, ev.link.dst.port_no
        try:
            bw = self.link_config[ev.link.src.port_no][ev.link.dst.port_no]["bw"]
            lat = self.link_config[ev.link.src.port_no][ev.link.dst.port_no]["lat"]
        except KeyError, e:
            bw = 100
            lat = 2

        bw *= self.BYTES_PER_MEGABIT * self.T1 # convert bandwidth to units of bytes per T1 seconds

        # check to see if this is a duplicate link add event
        try:
            self.graph.es.find(src_dpid=ev.link.src.dpid, dst_dpid=ev.link.dst.dpid)
            # self.graph.find(_source=str(ev.link.src.dpid),_target=str(ev.link.dst.dpid))
            #print "duplicate link add event"
            return
        except:
            pass

        self.graph.add_edge(str(ev.link.src.dpid), str(ev.link.dst.dpid),
            src_dpid=ev.link.src.dpid,
            dst_dpid=ev.link.dst.dpid,
            src_port=ev.link.src.port_no,
            dst_port=ev.link.dst.port_no,
            bw=bw,
            lat=lat,
            estimated_bw=bw,
            last_bws=deque(maxlen=self.S1),
            last_num_bytes=0)
        #print "Link added", ev.link
        #print self.graph

    def widest_dijkstra(self, g, s, bw='bw'):
        previous = {}  # previous hops
        cap = {}  # capacities between nodes
        T = set()
        V = set(range(g.vcount()))  # Initially set of all nodes
        T.add(s)
        V.remove(s)
        cap[s] = float(100 * self.BYTES_PER_MEGABIT * self.T1) # links from host to switch are always bw 100 but not included in our graph
        # Initialize capacities
        for v in V:
            es_sv = g.es.select(_source=s, _target=v)
            if es_sv.count_multiple() == [1]:
                cap[v] = es_sv[bw][0]
                previous[v] = s
            else:
                cap[v] = 0.0
        while len(V) > 0:
            u = max(V, key=lambda x: cap[x])
            T.add(u)
            V.remove(u)
            # update capacities
            for v in V:
                es_uv = g.es.select(_source=u, _target=v)
                if es_uv.count_multiple() == [1]:
                    bw_uv = es_uv[bw][0]
                    if cap[v] < min(cap[u], bw_uv):
                        cap[v] =  min(cap[u], bw_uv)
                        previous[v] = u
        return cap, previous

    def get_edges_from_prev(self, g, s, d, prev):
        edges = []
        curr = d
        while curr != s:
            # #print curr, g.vs[curr]['name']
            try:
                eid = g.es.find(_source=prev[curr], _target=curr).index
            except:
                return []
            edges.append(eid)
            curr = prev[curr]

        return edges[::-1]

    def widest_path(self, s, d, bw='bw'):
        cap, prev = self.widest_dijkstra(self.graph, s, bw)
        return self.get_edges_from_prev(self.graph, s, d, prev), cap[d]

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.T1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def check_flow(self, flow):
        if flow.priority != 1:
            return False
        try:
            flow.match['eth_type']
            flow.match['in_port']
            flow.match['eth_dst']
            flow.match['eth_src']
        except KeyError, e:
            return False
        else:
            return True

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        if self.flow_logging_on:
            self.logger.info('datapath         '
                             'in-port  eth-dst           '
                             'out-port packets  bytes  timeout')
            self.logger.info('---------------- '
                             '-------- ----------------- '
                             '-------- -------- -------- -------')

        for stat in sorted([flow for flow in body if self.check_flow(flow)],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            dpid = ev.msg.datapath.id
            in_port = stat.match['in_port']
            dst = stat.match['eth_dst']
            src = stat.match['eth_src']

            # initialize comm list entry if not yet initalized
            if self.comm_list.get(src) is None:
                self.comm_list[src] = {}

            if self.comm_list[src].get(dst) is None:
                self.comm_list[src][dst] = dict(src=src, dst=dst,
                                            packets=0, last_byte_count=0,
                                            prev_counts=deque(maxlen=self.S1),
                                            avg_bytes=0)

            # redistribute bookkeeping
            info = self.comm_list[src][dst]
            info['packets'] = stat.packet_count
            curr_bytes = stat.byte_count - info['last_byte_count']
            info['last_byte_count'] = curr_bytes
            info['prev_counts'].append(curr_bytes)
            info['avg_bytes'] = sum(info['prev_counts'])/self.S1

            if self.flow_logging_on:
                self.logger.info('%016x %8x %17s %8x %8d %8d %8d',
                                 ev.msg.datapath.id,
                                 stat.match['in_port'], stat.match['eth_dst'],
                                 stat.instructions[0].actions[0].port,
                                 stat.packet_count, stat.byte_count, stat.hard_timeout)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        if self.port_logging_on:
            self.logger.info('datapath         port     '
                             'rx-pkts  rx-bytes rx-error rx-drop'
                             'tx-pkts  tx-bytes tx-error tx-drop')
            self.logger.info('---------------- -------- '
                             '-------- -------- -------- -------- '
                             '-------- -------- -------- --------')
        port_byte_counts = defaultdict(int)
        for stat in sorted(body, key=attrgetter('port_no')):
            port_byte_counts[stat.port_no] += stat.tx_bytes

            if self.port_logging_on:
                self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d %8d %8d',
                                 ev.msg.datapath.id, stat.port_no,
                                 stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.rx_dropped,
                                 stat.tx_packets, stat.tx_bytes, stat.tx_errors, stat.tx_dropped)

        # estimate bandwidth of port
        for port in port_byte_counts:
            byte_count = port_byte_counts[port]
            src_vid = self.graph.vs["name"].index((str(ev.msg.datapath.id)))
            try:
                edge = self.graph.es.find(_source=src_vid, src_port=port)
            except ValueError, e:
                pass
            else:
                # book keeping for proactive rules
                last_bw_used = (byte_count - edge['last_num_bytes'])
                edge['last_bws'].append(max(edge['bw'] - last_bw_used, 0))
                edge['estimated_bw'] = sum(edge['last_bws'])/self.S1
                # #print 'src:', edge['src_dpid'], 'dst:', edge['dst_dpid'], 'bw:', edge['bw'], 'estimated_bw:', edge['estimated_bw']
                edge['last_num_bytes'] = byte_count

    def redistribute_thread(self):
        #print 'starting redistribute thread'
        while True:

            #print 'sleeping for', self.T2, 'seconds'
            sleep(self.T2)
            #print "Waited for", self.T2, "seconds"

            self.redistributing = True

            #print "REDISTRIBUTING!!!"
            self.redistribute()
            #print "done REDISTRIBUTING"

            self.redistributing = False

    def redistribute(self):
        # sort infos
        info_list = []
        for src in self.comm_list:
            for dst in self.comm_list[src]:
                info_list.append(self.comm_list[src][dst])

        info_list = sorted(info_list, key=lambda info:info['packets'], reverse=True)

        for info in info_list:
            #print info

        # restore estimates to initial capacity
        estimates = self.graph.es['estimated_bw']
        self.graph.es['estimated_bw'] = list(self.graph.es['bw'])

        flows = []
        for info in info_list:
            src = info['src']
            dst = info['dst']
            #print '-----------------------INFO\n\t', info
            dst_switch_dpid = self.hosts_to_switch[dst]
            src_switch_dpid = self.hosts_to_switch[src]

            dst_vid = self.graph.vs.find(name=str(dst_switch_dpid)).index
            src_vid = self.graph.vs.find(name=str(src_switch_dpid)).index

            cap, prev = self.widest_dijkstra(self.graph, src_vid, bw='estimated_bw')
            if cap[dst_vid] > 0:
                src_port = self.mac_to_port[src_switch_dpid][src]
                dst_port = self.mac_to_port[dst_switch_dpid][dst]
                # #print 'finding edges from vid', src_vid, 'to vid', dst_vid
                #print 'finding edges from switch_dpid', src_switch_dpid, 'to switch_dpid', dst_switch_dpid
                epath = self.get_edges_from_prev(self.graph, src_vid, dst_vid, prev)
                #print '\tpath(%d):' % (len(epath)),
                if len(epath) != 0:
                    for eid in epath:
                        #print self.graph.es[eid]['src_dpid'],
                    #print self.graph.es[epath[-1]]['dst_dpid']
                else:
                    #print self.hosts_to_switch[src]

                new_flows = self.get_flows(epath, src, dst, info)
                # new_flows = self.get_flows1(src_vid, dst_vid, src_port, dst_port, src, dst, prev, cap, info)
                if new_flows is None:
                    #print 'some hosts appeared to be unreachable, not redistributing'
                    # restore old estimates
                    self.graph.es['estimated_bw'] = estimates
                    return
                flows += new_flows
                # #print '\t----------------FLOWS:', len(flows)
                # #print '\t------------NEW_FLOWS:', len(new_flows)
                #print '\t\t', new_flows
            else:
                #print 'some hosts appeared to be unreachable, not redistributing'
                # restore old estimates
                self.graph.es['estimated_bw'] = estimates
                return

        # delete all flows
        for dpid in self.datapaths:
            #print "trying to delete flows"
            #print dpid
            self.delete_flow(self.datapaths[dpid])

        # install all the new flows
        for flow in flows:
            #print 'trying to install new flow on datapath', flow['dpid']
            #print '\tin_port', flow['in_port'], 'eth_src', flow['eth_src'], 'eth_dst', flow['eth_dst'], 'out_port', flow['out_port']
            datapath = self.datapaths[flow['dpid']]
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(flow['out_port'])]
            match = parser.OFPMatch(in_port=flow['in_port'],
                                    eth_dst=flow['eth_dst'],
                                    eth_src=flow['eth_src'])
            self.add_flow(datapath, 0, 1, match, actions)


    def bw_print(self, eid, bw_key='estimated_bw'):
        bw = self.graph.es[eid][bw_key]
        bw = bw /self.BYTES_PER_MEGABIT / self.T1
        #print self.graph.es[eid]['src_dpid'], '->', self.graph.es[eid]['dst_dpid'], bw

    def get_flows(self, epath, src, dst, info):
        flows = []

        # append flow for src
        dpid = self.hosts_to_switch[src]
        in_port = self.mac_to_port[dpid][src]

        if len(epath) == 0:
            if self.hosts_to_switch[dst] != dpid:
                return None

            out_port = self.mac_to_port[dpid][dst]
            flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

            return flows

        out_port = self.graph.es[epath[0]]['src_port']
        flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

        for i in xrange(len(epath)-1):
            es = self.graph.es[epath[i]]
            next_es = self.graph.es[epath[i+1]]

            # flow parameters
            dpid = es['dst_dpid']
            in_port = es['dst_port']
            out_port = next_es['src_port']

            # append the flow to be added later
            flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

            # updated the estimated_bw
            self.bw_print(epath[i])
            updated_bw = es['estimated_bw'] - info['avg_bytes']
            es['estimated_bw'] = max(0, updated_bw)
            self.bw_print(epath[i])

        # append flow for dst
        last_es = self.graph.es[epath[-1]]
        dpid = last_es['dst_dpid']
        in_port = last_es['dst_port']
        out_port = self.mac_to_port[dpid][dst]
        flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

        self.bw_print(epath[-1])
        updated_bw = last_es['estimated_bw'] - info['avg_bytes']
        last_es['estimated_bw'] = max(0, updated_bw)
        self.bw_print(epath[-1])

        return flows

    def get_flows1(self, src_vid, dst_vid, src_port, dst_port, src, dst, prev, cap, info):
        #print 'getting flows'
        curr = dst_vid
        out_port = dst_port

        flows = []

        while curr != src_vid:
            dpid = int(self.graph.vs[curr]['name'])

            try: eid = self.graph.es.find(_source=prev[curr], _target=curr).index
            except:
                #print "path not found, returning"
                return None

            in_port = self.graph.es[eid]['dst_port']
            flows.append(dict(dpid=dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))

            # update the estimated_bw
            updated_bw = self.graph.es[eid]['estimated_bw'] - info['avg_bytes']
            self.graph.es[eid]['estimated_bw'] = max(0, updated_bw)

            # update step
            out_port = self.graph.es[eid]['src_port']
            curr = prev[curr]

        # add the flow for the beginning
        in_port = src_port
        src_switch_dpid = int(self.graph.vs[src_vid]['name'])
        flows.append(dict(dpid=src_switch_dpid,in_port=in_port,out_port=out_port,eth_dst=dst,eth_src=src))
        return flows

    def get_edges_from_prev(self, g, s, d, prev):
        edges = []
        curr = d
        while curr != s:
            # #print curr, g.vs[curr]['name']
            try:
                eid = g.es.find(_source=prev[curr], _target=curr).index
            except:
                return []
            edges.append(eid)
            curr = prev[curr]

        return edges[::-1]