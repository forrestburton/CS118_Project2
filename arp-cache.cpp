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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

static const uint8_t broadcast_address[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // REMOVE

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
/**
 * This method gets called every second. For each request sent out,
 * you should keep checking whether to resend a request or remove it.
 */
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // FILL THIS IN

  // If ongoing traffic (client still pinging server)
  // Send ARP request about once a second until an ARP reply comes back or request has been sent out at least 5 times
  // If router didn't receive ARP reply after re-transmitting ARP request 5 times, it should stop re-transmitting, remove pending request
    // and also remove any packets that are queued for the transmission 
  
  int length = m_cacheEntries.size();
  std::cerr << "ARP Cache length is: " << length << std::endl;
  std::list<std::shared_ptr<ArpRequest>>::iterator request_it = m_arpRequests.begin();
  while (request_it != m_arpRequests.end()) {
    // Determine how many re-transmissions of ARP requests have occured
    const uint32_t sent_time = (*request_it)->nTimesSent;
    if (sent_time >= MAX_SENT_TIME) {  // stop retransmitting after 5 times and remove pending request
      // remove any packets that are queued for the transmission
      std::list<PendingPacket>::const_iterator packet_it = (*request_it)->packets.begin();
      while (packet_it != (*request_it)->packets.end()) {
        packet_it = (*request_it)->packets.erase(packet_it);
      }

      // remove pending request
      request_it = m_arpRequests.erase(request_it);  
    }
    // Send ARP request about once a second until an ARP reply comes back or request has been sent out at least 5 times
    else {
      // get interface
      std::string iname = (*request_it)->packets.front().iface;
      const Interface* interface = m_router.findIfaceByName(iname);
      
      // Buffer for ARP request
      Buffer packet_send_buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
          
      // create ptr for arp header 
      arp_hdr *arp_hdr_request = reinterpret_cast<arp_hdr *>(packet_send_buffer.data()+ sizeof(ethernet_hdr)); 
      // Add data for arp header
      arp_hdr_request->arp_hrd = htons(arp_hrd_ethernet);
      arp_hdr_request->arp_pro = htons(ethertype_ip);
      arp_hdr_request->arp_hln = ETHER_ADDR_LEN;
      arp_hdr_request->arp_pln = 4;
      arp_hdr_request->arp_op = htons(arp_op_request);  // Opcode of the reply
      arp_hdr_request->arp_sip = interface->ip;
      memcpy(arp_hdr_request->arp_tha, broadcast_address, ETHER_ADDR_LEN);  //CHANGE
      arp_hdr_request->arp_tip = (*request_it)->ip;  
      memcpy(arp_hdr_request->arp_sha, interface->addr.data(), ETHER_ADDR_LEN);

      // create ptr for ethernet header 
      ethernet_hdr *eth_hdr_request = reinterpret_cast<ethernet_hdr *>(packet_send_buffer.data()); 
      // Add data for ethernet header
      memcpy(eth_hdr_request->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
      memcpy(eth_hdr_request->ether_dhost, broadcast_address, ETHER_ADDR_LEN);  // CHANGE
      eth_hdr_request->ether_type = htons(ethertype_arp);

      // Send packet
      std::cerr << "Sending ARP Request to populate ARP cache" << std::endl;
      m_router.sendPacket(packet_send_buffer, interface->name);

      //update request information
      (*request_it)->nTimesSent++;
      (*request_it)->timeSent = std::chrono::steady_clock::now();
      request_it++;
    }
  }
  // If no ongoing traffic
  // Starter code already includes cfacility to mark ARP entries "invalid"
  // Loop through and remove invalid entries
  std::list<std::shared_ptr<ArpEntry>>::iterator it = m_cacheEntries.begin();
  while (it != m_cacheEntries.end()) {
    if (!((*it)->isValid)){
      it = m_cacheEntries.erase(it);
    }
    else {
      it++;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
