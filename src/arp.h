/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_ARP_H__
#define SRC_ARP_H__

#include <sstream>
#include "./rawsock.h"

namespace lurker {
  class ArpHandler : public swarm::Handler {
  private:
    static const u_int16_t ETHERTYPE_ARP =  0x0806;
    static const u_int16_t ETHERTYPE_IP  =  0x0800;
    static const size_t ETHER_ADDR_LEN = 6;
    static const size_t IPV4_ADDR_LEN  = 4;
    struct ether_header {
      u_int8_t dst_[ETHER_ADDR_LEN];
      u_int8_t src_[ETHER_ADDR_LEN];
      u_int16_t type_;
    } __attribute__((packed));

    static const u_int16_t ARPHRD_ETHER = 1; // Ethernet format
    static const u_int16_t ARPOP_REPLY  = 2; // response to previous request 
    struct arp_header {
      u_int16_t hw_addr_fmt_;
      u_int16_t pr_addr_fmt_;
      u_int8_t  hw_addr_len_;
      u_int8_t  pr_addr_len_;
      u_int16_t op_;
      u_int8_t  src_hw_addr_[ETHER_ADDR_LEN]; // MAC address
      u_int8_t  src_pr_addr_[IPV4_ADDR_LEN]; // IPv4 address
      u_int8_t  dst_hw_addr_[ETHER_ADDR_LEN]; // MAC address
      u_int8_t  dst_pr_addr_[IPV4_ADDR_LEN]; // IPv4 address
    } __attribute__((packed));

    swarm::NetDec *nd_;
    swarm::param_id op_;
    RawSock *sock_;

  public:
    ArpHandler(swarm::NetDec *nd);
    ~ArpHandler();
    bool open_dev(const std::string &dev_name);
    void recv(swarm::ev_id eid, const  swarm::Property &p);
  };

}


#endif  // SRC_ARP_H__
