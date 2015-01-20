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
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <msgpack.hpp>

#include "./swarm/swarm.h"
#include "./debug.h"
#include "./optparse.h"
#include "./arp.h"
#include "./pkt.h"

namespace lurker {

  ArpHandler::ArpHandler(swarm::Swarm *sw, TargetSet *target, Emitter *emitter) : 
    sw_(sw), sock_(NULL), emitter_(emitter), os_(NULL), target_(target) {
    assert(this->sw_);
    assert(this->target_);
    assert(this->emitter_);
    this->op_ = this->sw_->lookup_value_id("arp.op");
  }
  ArpHandler::~ArpHandler() {
    delete this->sock_;
  }

  void ArpHandler::set_sock(RawSock *sock) {
    this->sock_ = sock;
  }

  void ArpHandler::unset_sock() {
    this->sock_ = NULL;
  }

  void ArpHandler::set_out_stream(std::ostream *os) {
    this->os_ = os;
  }


  void ArpHandler::recv(swarm::ev_id eid, const  swarm::Property &p) {

    if (this->target_->has(p.value("arp.dst_pr").repr())) {

      bool reply = false;

      if (this->sock_) {
        size_t buf_len = sizeof(struct ether_header) + sizeof(struct arp_header);
        uint8_t *buf = reinterpret_cast<uint8_t *>(malloc(buf_len));

        struct ether_header *eth_hdr 
          = reinterpret_cast<struct ether_header*>(buf);
        struct arp_header *arp_hdr 
          = reinterpret_cast<struct arp_header*>(buf + sizeof(struct ether_header));
    
        memcpy(eth_hdr->dst_, p.value("ether.src").ptr(), ETHER_ADDR_LEN);
        eth_hdr->type_ = htons(ETHERTYPE_ARP);

        arp_hdr->hw_addr_fmt_ = htons(ARPHRD_ETHER);
        arp_hdr->pr_addr_fmt_ = htons(ETHERTYPE_IP);
        arp_hdr->hw_addr_len_ = 6;
        arp_hdr->pr_addr_len_ = 4;
        arp_hdr->op_ = htons(ARPOP_REPLY);

        memcpy(arp_hdr->src_hw_addr_, this->sock_->hw_addr(), ETHER_ADDR_LEN);
        memcpy(arp_hdr->src_pr_addr_, p.value("arp.dst_pr").ptr(), IPV4_ADDR_LEN);
        memcpy(arp_hdr->dst_hw_addr_, p.value("arp.src_hw").ptr(), ETHER_ADDR_LEN);
        memcpy(arp_hdr->dst_pr_addr_, p.value("arp.src_pr").ptr(), IPV4_ADDR_LEN);

        memcpy(arp_hdr->src_hw_addr_, this->sock_->hw_addr(), ETHER_ADDR_LEN);
        this->sock_->write(buf, buf_len);
        free(buf);
        reply = true;
      }

      if (this->emitter_) {
        msgpack::sbuffer buf;
        msgpack::packer<msgpack::sbuffer> pk(&buf);
        pk.pack_map(7);

        pk.pack(std::string("ts"));
        pk.pack(p.ts());

        pk.pack(std::string("src_addr"));
        pk.pack(p.value("arp.src_pr").repr());
        pk.pack(std::string("dst_addr"));
        pk.pack(p.value("arp.dst_pr").repr());

        pk.pack(std::string("src_hw"));
        pk.pack(p.value("arp.src_hw").repr());
        pk.pack(std::string("dst_hw"));
        pk.pack(p.value("arp.dst_hw").repr());

        pk.pack(std::string("event"));
        pk.pack(std::string("ARP-REQ"));

        pk.pack(std::string("replied"));
        pk.pack(reply);

        this->emitter_->emit(buf);
      }

      if (this->os_) {
        *(this->os_) << "ARP recv: who-has " << p.value("arp.dst_pr").repr() << " from "
                     << p.value("arp.src_pr").repr() << " [" << p.value("arp.src_hw").repr() 
                     << "]" << std::endl;
      }
    } 

  }
}

