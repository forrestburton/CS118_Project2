/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
/**
* IMPLEMENT THIS METHOD
*
* This method is called each time the router receives a packet on
* the interface.  The packet buffer \p packet and the receiving
* interface \p inIface are passed in as parameters. The packet is
* complete with ethernet headers.
*/
std::string BROADCAST = "FF:FF:FF:FF:FF:FF";
std::string LOWER_BROADCAST = "ff:ff:ff:ff:ff:ff";
int PORT_SIZE = 16;
static const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // REMOVE

void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)   
{
  print_hdrs(packet);
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // Get MAC address information
  // macToString: Get formatted Ethernet address, e.g. 00:11:22:33:44:55
  std::string iface_mac_address = macToString(iface->addr);
  std::string destination_mac_address = macToString(packet);

  //ignoring condition: if packet not destined for the router
  if ((destination_mac_address != iface_mac_address) && (destination_mac_address != BROADCAST) && (destination_mac_address != LOWER_BROADCAST)) {
    std::cerr << "Ethernet frames must be destined for the MAC address of the interface or a braodcast address" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // Determine if packet is ARP or IPv4
  uint16_t ethtype = ethertype(packet.data());

  // IF ARP
  if (ethtype == ethertype_arp) {
    std::cerr << "ARP Packet" << std::endl;

    // Check packet size is valid
    unsigned long required_p_size = packet.size();
    unsigned long p_size = sizeof(ethernet_hdr) + sizeof(arp_hdr);
    if (required_p_size < p_size) {
      std::cerr << "Droping packet: ARP packet too small" << std::endl;
      return;
    } 
    
    const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
    unsigned short arp_op = hdr->arp_op;
    // ntohs converts networking byte routing ordering to machine byte ordering (dependent on systems architecture MSB or LSB)
    // Determine if request or reply
    uint16_t arp_opcode = ntohs(arp_op);

    // If request (uses unicast for source and broadcast for destination)
    if (arp_opcode == arp_op_request) {
      std::cerr << "This is an ARP Request" << std::endl;
      uint32_t arp_tip = hdr->arp_tip;
      uint32_t iface_ip = iface->ip;

      // Must properly respond to ARP requests for MAC address for the IP address of the corresponding network interface
      if (arp_tip != iface_ip) {
        std::cerr << "For ARP requests, ignore if the target IP address of ARP request and receiving interface do not match" << std::endl;
        return;
      }

      // Buffer to send packets 
      Buffer packet_send_buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      // create ptr for ethernet header 
      ethernet_hdr * eth_hdr_reply = reinterpret_cast<ethernet_hdr *>(packet_send_buffer.data()); 
      // create ptr for arp header 
      arp_hdr * arp_hdr_reply = reinterpret_cast<arp_hdr *>(packet_send_buffer.data()+ sizeof(ethernet_hdr)); 
      
      // Add data for ethernet header
      memcpy(eth_hdr_reply->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(eth_hdr_reply->ether_dhost, &(hdr->arp_sha), ETHER_ADDR_LEN);  // PULL OUT variables?
      eth_hdr_reply->ether_type = htons(ethertype_arp);
      
      // Add data for arp header
      arp_hdr_reply->arp_hrd = htons(arp_hrd_ethernet);
      arp_hdr_reply->arp_pro = htons(ethertype_ip);
      arp_hdr_reply->arp_hln = ETHER_ADDR_LEN;
      arp_hdr_reply->arp_pln = 4;
      arp_hdr_reply->arp_op = htons(arp_op_reply);  // Opcode of the reply
      arp_hdr_reply->arp_sip = iface->ip;
      memcpy(arp_hdr_reply->arp_tha, &(hdr->arp_sha), ETHER_ADDR_LEN);
      arp_hdr_reply->arp_tip = hdr->arp_sip;
      memcpy(arp_hdr_reply->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      
      std::cerr << "Sending ARP Response in response to an ARP Request" << std::endl;
      sendPacket(packet_send_buffer, iface->name);
    }
    // If reply (uses unicast for source and unicast for destination)
    else if (arp_opcode == arp_op_reply) { 
      std::cerr << "This is an ARP Reply" << std::endl;
      
      // record IP-MAC mapping information in ARP cache (Source IP/Source hardware address in the ARP reply)
      Buffer ip_mac_mapping(ETHER_ADDR_LEN);  // mapping info to be stored in ARP cache
      memcpy(ip_mac_mapping.data(), hdr->arp_sha, ETHER_ADDR_LEN);
      
      // Afterwards, the router should send out all corresponding enqueued packets
      std::shared_ptr<ArpEntry> lookup_ptr = m_arp.lookup(hdr->arp_sip);  // Lookup entry in ARP cache
      if (lookup_ptr == NULL) {  // not in ARP cache
        uint32_t sender_ip_address = hdr->arp_sip;
        std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(ip_mac_mapping, sender_ip_address);
        
        // send all correspending packets in the queue 
        if (req != NULL) {
          for (std::list<PendingPacket>::iterator i = req->packets.begin(); i != req->packets.end(); i++) {
            ethernet_hdr* ethernet_header = (ethernet_hdr*) i->packet.data();

            memcpy(ethernet_header->ether_dhost, hdr->arp_sha, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

            std::cerr << "Sending all ARP packets in the queue" << std::endl;            
            sendPacket(i->packet, i->iface);
          }
        }
        // remove
        m_arp.removeArpRequest(req);
      }
    }
  }
  // IF IPv4
  else if (ethtype == ethertype_ip) {
    std::cerr << "Ipv4 Request" << std::endl;
    // Check packet size is valid

    Buffer buf(packet);  // buffer for IPv4 packet
    ip_hdr* ip_header = (ip_hdr*) (buf.data() + sizeof(ethernet_hdr));

    unsigned long required_p_size = packet.size();
    unsigned long p_size = sizeof(ethernet_hdr) + sizeof(ip_hdr);
    if ((required_p_size < p_size) || (ip_header->ip_len < sizeof(ip_hdr))) {
      std::cerr << "Droping packet: IPv4 packet too small" << std::endl;
      return;
    } 

    uint16_t old_checksum = ip_header->ip_sum; //Old checksum
    ip_header->ip_sum = 0; //reset
    if (old_checksum != cksum(ip_header, sizeof(ip_hdr))) {
      std::cerr << "Dropping Packet: checksum error" << std::endl;
      return;
    }

    // ACL CHECK
    // Check if any ACL rules apply to packet
    uint16_t* source_port;
    uint16_t* destination_port;
    
    // If the packet is an ICMP packet, both port numbers will be zero.
    *source_port = 0;
    *destination_port = 0;

    // If the packet is a TCP or UDP packet, the srcPort number and dstPort number should be extracted from the TCP/UDP header which is right behind the IP header.
    if (ip_header->ip_p == 0x06 || ip_header->ip_p == 0x11) {  // 0x06 = TCP, 0x11 = UDP
      memcpy(source_port, ip_header + sizeof(ip_hdr), PORT_SIZE);
      memcpy(destination_port, ip_header + sizeof(ip_hdr) + PORT_SIZE, PORT_SIZE);
    } 

    uint32_t ip_source = ip_header->ip_src;
    uint32_t ip_destination = ip_header->ip_dst;
    uint8_t ip_protocal = ip_header->ip_p;
    ACLTableEntry entry = m_aclTable.lookup(ip_source, ip_destination, ip_protocal, *source_port, *destination_port);
    
    // entry->action == "" means not found in ACL table
    if (entry->action == "") {
      // Perform action described by packet: "Deny" or "Permit"
      if (entry.action == "Deny") {
        // log if packet dropped
        m_aclLogFile; << entry << '\n';  // FORMATTED CORRECTLY???
        std::cerr << "Dropping packet: ACL rule says to deny" << std::endl;
        return;
      }
    }

    // (1) if destined for router -> packets should be discarded
    for (auto iface = m_ifaces.begin(); iface != m_ifaces.end(); iface++) {  
      // Check if packet is destined for router and drop it if so
      ip_destination = ip_header->ip_dst;
      if (iface->ip == ip_destination) {
        std::cerr << "Ignoring packet: Packet destined for the router" << std::endl;
        return;
      }
    }

    // (2) datagrams to be forwarded -> use longest prefix algorithm to find a next-hop IP address in routing table
    // Check TTL
    std::cerr << "Checking TTL" << std::endl;

    // if 0 -> drop
    if (ip_header->ip_ttl <= 0) {
      std::cerr << "Ignoring Packet: TTL of packet is 0" << std::endl;
      return;
    }
    std::cerr << "Decrementing TTL" << std::endl;
    //Decrement TTL
    ip_header->ip_ttl--; 
    // if > 0 -> recompute checksum
    ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr)); 
    
    //Use the longest prefix match algorithm to find a next-hop IP address in the routing table and attempt to forward it there
    std::cerr << "Checking routing table and using longest matching prefix algorithm" << std::endl;
    uint32_t ip_destination = ip_header->ip_dst;
    RoutingTableEntry table_entry = m_routingTable.lookup(ip_destination); // Use longest-prefix to find next-hop IP address
    
    const Interface *ip_interface_next = findIfaceByName(table_entry.ifName);
    std::shared_ptr<ArpEntry> lookup_ptr = m_arp.lookup(table_entry.gw); // Lookup entry in ARP cache
    std::string interface_name = ip_interface_next->name;

    //  Entry not in ARP cache, do ARP request
    if (lookup_ptr == NULL) {
      m_arp.queueArpRequest(table_entry.gw, packet, interface_name);  // Adds an ARP request to the ARP request queue  CHECK PACKET ???????
      
      // buffer for ARP request
      Buffer arp_buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));  
      
      // Ethernet header info
      ethernet_hdr* request_header_eth = (ethernet_hdr*) (arp_buffer.data());  // ARP_BUFFER OR PACKET???????
      request_header_eth->ether_type = htons(ethertype_arp);
      memcpy(request_header_eth->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);  // ???????
      memcpy(request_header_eth->ether_shost, ip_interface_next->addr.data(), ETHER_ADDR_LEN);
      

      // ARP header info 
      arp_hdr* request_header_arp = (arp_hdr*) (buf.data() + sizeof(ethernet_hdr));  // PACKET OR???????
      request_header_arp->arp_pro = htons(ethertype_ip);
      request_header_arp->arp_hrd = htons(arp_hrd_ethernet);
      request_header_arp->arp_op = htons(arp_op_request);
      request_header_arp->arp_sip = ip_interface_next->ip;
      request_header_arp->arp_tip = table_entry.gw;
      request_header_arp->arp_hln = ETHER_ADDR_LEN;
      request_header_arp->arp_pln = 4;
      memcpy(request_header_arp->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);   // ???????
      memcpy(request_header_arp->arp_sha, ip_interface_next->addr.data(), ETHER_ADDR_LEN);

      std::cerr << "Forwarding IPv4 Packet" << std::endl;
      sendPacket(arp_buffer, interface_name);
    }  
    // Entry already in ARP cache
    else {
      // Determine MAC Address, then forward 
      ethernet_hdr* ip_ethernet_header = (ethernet_hdr*) (packet.data());
      memcpy(ip_ethernet_header->ether_shost, ip_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
      memcpy(ip_ethernet_header->ether_dhost, lookup_ptr->mac.data(), ETHER_ADDR_LEN);
      ip_ethernet_header->ether_type = htons(ethertype_ip);

      std::cerr << "Forwarding IPv4 Packet" << std::endl;
      sendPacket(packet, interface_name);
    }
  }
  // OTHERWISE, ignoring: Packet must be either ARP or IPv4
  else { 
    std::cerr << "Ignoring Packer: Packet must be ARP or IPv4" << std::endl;
    return;
  }
  m_aclLogFile.close();  // Close stream
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
