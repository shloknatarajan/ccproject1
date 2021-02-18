from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link
import copy
import networkx as nx

class ProjectOne(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(ProjectOne, self).__init__(*args, **kwargs)
		# USed for learning switch functioning
		self.mac_to_port = {}
		# Holds the topology data and structure
		self.topo_raw_switches = []
		self.topo_raw_links = []
		self.net=nx.DiGraph()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		self.logger.info('OFPSwitchFeatures received: '
						 '\n\tdatapath_id=0x%016x n_buffers=%d '
						 '\n\tn_tables=%d auxiliary_id=%d '
						 '\n\tcapabilities=0x%08x',
						 msg.datapath_id, msg.n_buffers, msg.n_tables,
						 msg.auxiliary_id, msg.capabilities)

		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	# We are not using this function
	def delete_flow(self, datapath):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		for dst in self.mac_to_port[datapath.id].keys():
			match = parser.OFPMatch(eth_dst=dst)
			mod = parser.OFPFlowMod(
				datapath, command=ofproto.OFPFC_DELETE,
				out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
				priority=1, match=match)
			datapath.send_msg(mod)

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

	"""
	This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
	tells Ryu when the decorated function should be called.
	"""
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
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

		dst = eth.dst
		src = eth.src
	
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		# self.logger.info("\tpacket in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		# if dst in self.mac_to_port[dpid]:
		# 	out_port = self.mac_to_port[dpid][dst]
		# else:
		# 	out_port = ofproto.OFPP_FLOOD
 
		if src not in self.net: #Learn it
			self.net.add_node(src) # Add a node to the graph
			self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
			self.net.add_edge(dpid,src,{'port':msg.in_port})  # Add link from switch to node and make sure you are identifying the output port.
		if dst in self.net:
			path=nx.shortest_path(self.net,src,dst) # get shortest path  
			next=path[path.index(dpid)+1] #get next hop
			out_port=self.net[dpid][next]['port'] # get output port
		else:
			out_port = ofproto.OFPP_FLOOD
			# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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

		actions = [parser.OFPActionOutput(out_port)]
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)

	###################################################################################
	"""
	The event EventSwitchEnter will trigger the activation of get_topology_data().
	"""
	@set_ev_cls(event.EventSwitchEnter)
	def handler_switch_enter(self, ev):
		# self.graph.add_node(ev.switch.dp.id)
		# print("Switch with DPID %d has been added." % (ev.switch.dp.id))
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_nodes_from(switches)
		self.net.add_edges_from(links)

	# @set_ev_cls(event.EventLinkDelete)
	# def handler_link_delete(self, ev):
	# 	self.graph.add_edge(self.get_node_object(ev.link.src), self.get_node_object(ev.link.dst))

	# @set_ev_cls(event.EventLinkAdd)
	# def handler_link_add(self, ev):
	# 	self.graph.remove_edge(self.get_node_object(ev.link.src), self.get_node_object(ev.link.dst))

	# @set_ev_cls(event.EventHostAdd)
	# def handler_host_add(self, ev, dir):
	# 	self.graph.add_node(ev.host.mac)
	# 	print("host with mac %s has been added" %(ev.host.mac))


	def get_node_object(self, item):
		if 'mac' in item.to_dict().keys():
			return item.mac
		else:
			return item.dpid
	"""
	This event is fired when a switch leaves the topo. i.e. fails.
	"""
	@set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
	def handler_switch_leave(self, ev):
		self.graph.remove_node(ev.switch.dp.id)
		print("Switch with DPID %d has been removed." % (ev.switch.dp.id))