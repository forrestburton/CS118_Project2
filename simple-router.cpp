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
    
    const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));

    unsigned short arp_op = hdr->arp_op;
    // ntohs converts networking byte routing ordering to machine byte ordering (dependent on systems architecture MSB or LSB)
    // Determine if request or reply
    uint16_t arp_opcode = ntohs(arp_op);

    // If request (uses unicast for source and broadcast for destination)
    if (arp_opcode == arp_op_request) {
      uint32_t arp_tip = hdr->arp_tip;
      uint32_t iface_ip = iface->ip;

      // Must properly respond to ARP requests for MAC address for the IP address of the corresponding network interface
      if (arp_tip != iface_ip) {
        std::cerr << "For ARP requests, ignore if the target IP address of ARP request and receiving interface do not match" << std::endl;
        return;
      }
      

    }
    else if (arp_opcode == arp_op_reply) {  // If reply (uses unicast for source and unicast for destination)

    }
  }
  

  // Ignore frames not ARP or Ipv4

  // IF IP
    // if destined for router
    // Else check TTL
    // if 0 -> drop
    // if > 0 -> recompute checksum, longest matching prefix algorithm

  // OTHERWISE, Error: Packet must be either ARP or IPv4


  //  Check that iface address correspends to packet address

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
