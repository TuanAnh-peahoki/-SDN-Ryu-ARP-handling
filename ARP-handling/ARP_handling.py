from codecs import ignore_errors
from distutils.command.install_scripts import install_scripts
from re import L, S
from tokenize import Ignore
from typing import Any
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet ,ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp, lldp, icmpv6
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import ryu.app.ofctl.api as ofctl_api
import math

import datetime
import copy
flow_idle_timeout=10 #idle timout for the flow

class Report(app_manager.RyuApp):
    OFP_VERSIONS= [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self,*args,**kwargs):
        super(Report,self).__init__(*args,**kwargs)

        self.MAC_table  = {} # Create blank MAC table 
        self.ARP_table  =   {} # Create blank ARP table

      
        self.datapaths  =   {} # Create the datapths table

        self.Topology_db = {} # Create the topology database
        self.network_changed_thread=None
        self.port_switch={}
        self.port_host={}


        self.switch_port_connect= []
        self.port_host_connect=[]
        self.learn_dict={}
        self.save_switch_request=[]

    ##############################################################
    # Add action for "missing flow"
    #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def action_for_missing_flow(self, ev):
        msg         =     ev.msg
        datapath          =     msg.datapath
        ofproto     =     datapath.ofproto
        ofp_parser  =     datapath.ofproto_parser
        match       =     ofp_parser.OFPMatch()
        
        actions         =    [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        instructions    = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.flow_add(datapath,0,0,None,instructions)

    ##############################################################  
    # Store and Map "Datapath" and "Datapath ID"
    #
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def StateChange(self, ev):
        dp   = ev.datapath
        dpid = dp.id
        
        if ev.state == MAIN_DISPATCHER:
            self.datapaths.setdefault(dpid,dp)
            
        if ev.state == DEAD_DISPATCHER:
            if (self.datapaths):
                self.datapaths.pop(dpid)

    ##############################################################
    # Handle PACKET-IN message
    #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
    def packet_in_handler(self,ev):
        msg =   ev.msg
        dp  =   msg.datapath
        ofp =   dp.ofproto
        ofp_parser  =   dp.ofproto_parser

        pkt =   packet.Packet(msg.data) #Get Packet
        etherh  =   pkt.get_protocol(ethernet.ethernet)     # Ethernet Header         
        smac    =   etherh.src                              # Source MAC address
        dmac    =   etherh.dst                              # Destination MAC address
        pin     =   msg.match['in_port']                    # port in
        pout    =   0                                       # port out doesn't know at first
        dpid    =   dp.id                                   # Switch ID

        #***
        #Ignore LLDP, ICMPv6 packets
        if pkt.get_protocol(lldp.lldp) or pkt.get_protocol(icmpv6.icmpv6):
            return

        print("\n OFC receives Packet-In message from Datapath ID of {} ------ Log at:{}".format(dpid,datetime.datetime.now))

        #Learn source MAC address and port
        # *** Only at the edge OFS
        self.MAC_table.setdefault(dpid,{})
        if(self.MAC_table[dpid].get(smac) !=  pin):
            self.MAC_table[dpid][smac]    =   pin
            self.MAC_table[dpid][smac]    =   pin
            print("   - Updates MAC table: MAC={} <-> Port{}".format(smac,pin))
        
        #Handle the ARP packet
        # 1. Learn the MAC address <--> IPv4 Address (ARP table)
        # 2. If Controller's ARP table already has the Destination MAC address and Destination IPv4 address
        # OFC creates the ARP reply and forward to the End Host via the Packetout message
        self.arp_handling(in_dpid=dpid,in_pin=pin, in_smac=smac, in_dmac=dmac,in_ofp_parser=ofp_parser,in_dp=dp,in_ofp=ofp,in_etherh=etherh,in_pkt=pkt,datapaths=dp,out_port=pout)
    

    ##############################################################
    # Handle ARP request protocol
    #
    def arp_handling(self,in_dpid,in_pin,in_smac,in_dmac,in_ofp_parser,in_dp,in_ofp,in_etherh,in_pkt,datapaths,out_port):
        arp_pkt=in_pkt.get_protocol(arp.arp)
        if arp_pkt:
            _sip = arp_pkt.src_ip
            _dip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REQUEST:
                print ("   - Receives a ARP request packet from host {} ({}) aksing the MAC of {}". format(_sip,in_smac,_dip))
                # Update ARP table
                self.ARP_table.setdefault(in_dpid,{})
                if (self.ARP_table[in_dpid].get(in_smac)    !=  _sip):
                    self.ARP_table[in_dpid][in_smac]    =   _sip
                    print("      + Update ARP table: MAC={} <--> IPv4={}".format(in_smac,_sip))
                    self.save_switch_request.append(in_dpid)
                    have_arp_info=False
                    
                    #Create ARP reply packet and send it to the request Host
                    for _dpid in self.ARP_table.keys():
                        if _dip in self.ARP_table[_dpid].values():
                            for _dmac in self.ARP_table[_dpid].keys():
                                if self.ARP_table[_dpid][_dmac] ==   _dip:
                                    break
                                
                                print("   +Creates and returns the ARP reply packet: IPv4={} <--> MAC={}".format(_dip,_dmac))
                                have_arp_info=True

                                e   =   ethernet.ethernet(dst=in_smac,src=_dmac,ether_types=in_etherh.ETH_TYPE_ARP)
                                a   =   arp.arp ( hwtype=1,proto=0x0800,hlen=6,plen=4,opcode=2,
                                                    
                                                src_mac=_dmac, src_ip=_dip,
                                                dst_mac=in_smac, dst_ip=_sip)
                                                
                                                                                
                                p=packet.Packet()
                                p.add_protocol(e)
                                p.add_protocol(a)
                                p.serialize()
                                
                                actions = [in_ofp_parser.OFPActionOutput(in_pin)]
                                out     = in_ofp_parser.OFPPacketOut(datapath=in_dp,buffer_id=in_ofp.OFP_NO_BUFFER,
                                                                    in_port=in_ofp.OFPP_CONTROLLER,actions=actions, data=p.data)

                                in_dp.send_msg(out)
                            
                                break
                        if (not have_arp_info):
                            print("      + {} is not in ARP table".format(_dip))
                            self.ARP_MAC_not_in_table(dpid=in_dpid,smac=in_smac,sip=_sip,dip=_dip,ipin=in_pin)
    ##############################################################
    # Handle ARP reply message
    #        
            if arp_pkt.opcode == arp.ARP_REPLY:
                print ("   - Receives a ARP reply packet from host {} ({}) answering the MAC of {}". format(_sip,in_smac,_dip))
                # Update ARP table
                self.ARP_table.setdefault(in_dpid,{})
                if (self.ARP_table[in_dpid].get(in_smac)    !=  _sip):
                    self.ARP_table[in_dpid][in_smac]    =   _sip
                    print("      + Update ARP table: MAC={} <--> IPv4={}".format(in_smac,_sip))
                #Create ARP reply packet and send it to the request Host
                    for m in range(len(self.ARP_table)):
                        if  self.ARP_table.values()[m].values()[0] == _dip:
                            if self.ARP_table.values()[m].keys()[0] == in_dmac:
                              for datapath_id in self.datapaths.keys():
                                  if self.ARP_table.keys()[m] == datapath_id:
                                      for l in range(len(self.MAC_table)):
                                        if self.MAC_table.keys()[l] == datapath_id:
                                            for n in range(len(self.MAC_table.values()[l])):
                                                if self.MAC_table.values()[l].keys()[n] == in_dmac:
                                                    print("   -Creates and return the ARP reply packet: IPv4={} <--> MAC={}".format(_dip,in_dmac))
                                                        
                                                    e   =   ethernet.ethernet(dst=in_smac,src=in_dmac,ethertype=ether.ETH_TYPE_ARP)
                                                    a   =   arp.arp ( hwtype=1,proto=0x0800,hlen=6,plen=4,opcode=2,
                                                                            
                                                                        src_mac=in_dmac, src_ip=_dip,
                                                                        dst_mac=in_smac, dst_ip=_sip)
                                                    print("-------------------------------------------------------------------")
                                                    print("     => Sending ARP Reply Packet to Switch {} - port {}".format(datapath_id,self.MAC_table.values()[l].values()[n]))
                                                    print("-------------------------------------------------------------------")
                                                    
                                                    p=packet.Packet()
                                                    p.add_protocol(e)
                                                    p.add_protocol(a)
                                                    p.serialize()

                                                    ############################################################################################################
                                                    # Send ARP reply packet to inform the Request Host about the destination MAC address of the destination host
                                                    #
                                                    actions = [in_ofp_parser.OFPActionOutput(self.MAC_table.values()[l].values()[n])]
                                                    out     = in_ofp_parser.OFPPacketOut(datapath=self.datapaths.values()[m],buffer_id=in_ofp.OFP_NO_BUFFER,
                                                                                    in_port=self.MAC_table.values()[l].values()[n],actions=actions, data=p.data)
                               
                                                    self.datapaths.values()[m].send_msg(out)
                                                    print("Successfully sending Packet out")
                                                    print("")
                                                    print("      + FlowMod (ADD) of Datapath ID={}, Match: (Dst. MAC={}, IPv4={}), Action: (PortOut={})".format(
                                                    datapath_id, in_smac,_sip ,in_pin ))    
                                                    ############################################################################################################
                                                    # Send Flow Mod to add new flow entry to Flow table
                                                    #
                                                    action = [in_ofp_parser.OFPActionOutput(in_pin)] 
                                                    match   = in_ofp_parser.OFPMatch(ipv4_dst=_sip, eth_dst= in_smac, eth_type=0x0800)

                                                    instructions    = [in_ofp_parser.OFPInstructionActions(in_ofp.OFPIT_APPLY_ACTIONS, action)]
                                                    mod     = in_ofp_parser.OFPFlowMod(datapath=self.datapaths.values()[m], command=in_ofp.OFPFC_ADD, 
                                                                                            priority=None,            
                                                                                        match=match,instructions=instructions)

                                                    self.datapaths.values()[m].send_msg(mod)
                                                    print("Successfully sending mod")                   
                                                    break
                           
                    
           
    ##############################################################
    # Handle ARP if the destination MAC address doesn't learn yet
    #
    def ARP_MAC_not_in_table(self,dpid,smac,sip,dip,ipin):
        p=packet.Packet()
        e=ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,src=smac,dst='FF:FF:FF:FF:FF:FF') # source MAC address cua h1, broadcast MAC address 
        a=arp.arp(hwtype=1,proto=0x0800,hlen=6,plen=4,opcode=1,
                                        src_mac=smac,src_ip=sip,
                                        dst_mac='FF:FF:FF:FF:FF:FF',dst_ip=dip)
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        count=0
        count_len=0
        for datapath_id in self.datapaths.keys():
            count=0
            if datapath_id in self.port_host.keys():
                if datapath_id == int(dip.split('.')[2]):
                    for l in range(len(self.port_host.keys())):                
                        if count_len == l:
                            count_len=count_len+1
                            if count_len == datapath_id:
                                for m in range(len(self.port_host.values()[l])):
                                    if count !=len(self.port_host.values()[l]):
                                        count=count+1
                                        if self.port_host.values()[l][m] == ipin and datapath_id == dpid :
                                            continue
                                        else:
                                            port_out=self.port_host.values()[l][m]
                                            print("-------------------------------------------------------------------")
                                            print("     => Sending ARP Request Packet to Switch {} - port {}".format(datapath_id,port_out))
                                            print("-------------------------------------------------------------------")
                                            
                                            ofproto=self.datapaths.values()[datapath_id-1].ofproto
                                            ofp_parser=self.datapaths.values()[datapath_id-1].ofproto_parser
                                            actions=[ofp_parser.OFPActionOutput(port_out)]
                                            out=ofp_parser.OFPPacketOut(datapath=self.datapaths.values()[datapath_id-1],buffer_id=ofproto.OFP_NO_BUFFER,
                                                                                                                in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=p.data)
                                            self.datapaths.values()[datapath_id-1].send_msg(out)
                                            
                                    else:
                                        count=0
                                        break
                                    continue
                                break
                    continue
              

    """
    Network Topology
    """
    
    ##############################################################
    # Network Changed:
    #   1. Switch is added or removed/unavailable
    #   2. Port status is changed (UP/DOWN)
    #

    #######################################
    # 1a. Switch is added
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        print("\nSwitch entering (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
          hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)

    #######################################
    # 1b. Switch is removed/unavailable
    @set_ev_cls(event.EventSwitchLeave)
    def handler_switch_leave(self, ev):
        print("\nSwitch leaving (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
          hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)

    #######################################
    # Update the topology
    #   * No care end hosts
    # 
    def network_changed(self):
        print("\nNetwork is changed------------------------------- Log at: {}".format(datetime.datetime.now()))
        self.topo_raw_switches = get_switch(self, None)
        self.topo_raw_links = get_link(self, None)
        
        print("\nCurrent Switches:")
        for s in self.topo_raw_switches:
            print (str(s))
        print("\nCurrent Links:")
        for l in self.topo_raw_links:
            print (str(l))
        self.BuildTopology()
    #######################################
    # Build topology
    # 
    def BuildTopology(self):
        self.Topology_db.clear()

        for l in self.topo_raw_links:
            _dpid_src = l.src.dpid
            _dpid_dst = l.dst.dpid
            _port_src = l.src.port_no
            _port_dst = l.dst.port_no
            
            self.Topology_db.setdefault(_dpid_src,{})
            self.Topology_db[_dpid_src][_dpid_dst] = [_port_src]
        print("")
        print("   - Topology Database: {}".format(self.Topology_db))

        for l in self.topo_raw_switches:
            dpid_src=l.dp.id
            self.switch_port_connect=[]
            for m in range(len(l.ports)):
                
                self.port_connect = l.ports[m].port_no
                m=m+1
                self.switch_port_connect.append(self.port_connect)
                
            self.port_switch[dpid_src]=self.switch_port_connect   
        print("")
        print("   - Switch Database: {}".format(self.port_switch))
        print("")
        
        count=0
        count_1=0
        for l in self.port_switch.keys():            
            for z in self.port_switch.values()[l-1]:
                for m in self.Topology_db[l].values():
                    p=self.Topology_db[l].values()[count][0]
                    count=count+1
                
                    if p !=z:
                        count_1=count_1+1
                        if count_1 == len(self.Topology_db[l].values()):
                            self.host_connect=z
                            self.port_host_connect.append(self.host_connect)
                            self.port_host[self.port_switch.keys()[l-1]]=self.port_host_connect     
                    else:
                        self.port_host_connect=[]    
                        count=0
                        break
                count=0             
                count_1=0
                    
        print("")
        print("   - Host-port Database: {}".format(self.port_host))
                                                     
    #######################################
    # Add Flow
    # 
    def flow_add(self, dp, idle_timeout, priority, match, instructions):
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser
        mod        = ofp_parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_ADD, 
                                           idle_timeout=idle_timeout, priority=priority, 
                                           
                                           match=match, instructions=instructions)
        if priority==0:
            in_port = "Any"
            eth_dst = "Any"
        else:
            in_port = match["in_port"]
            eth_dst = match["eth_dst"]
        #
        print("      + FlowMod (ADD) of Datapath ID={}, Match: (Dst. MAC={}, PortIn={}), Action: (PortOut={})".format(
            dp.id, eth_dst, in_port, instructions[0].actions[0].port))

        dp.send_msg(mod)
    
    #######################################
    # Count the number of switches
    # 
    def switches_count(self):
        return len(self.topo_raw_switches)


