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
#include "./arp.h"
#include "./pkt.h"

namespace lurker {

  ArpHandler::ArpHandler(swarm::Swarm *sw, TargetSet *target) : 
    sw_(sw), sock_(nullptr), target_(target), logger_(nullptr) {
    assert(this->sw_);
    assert(this->target_);
    this->op_ = this->sw_->lookup_value_id("arp.op");
  }
  ArpHandler::~ArpHandler() {
    delete this->sock_;
  }

  void ArpHandler::set_sock(RawSock *sock) {
    this->sock_ = sock;
  }

  void ArpHandler::unset_sock() {
    this->sock_ = nullptr;
  }

  void ArpHandler::set_logger(fluent::Logger *logger) {
    this->logger_ = logger;
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
        if (this->sock_->write(buf, buf_len) < 0) {
          fluent::Message *msg = this->logger_->retain_message("lurker.error");
          msg->set("message", this->sock_->errmsg());
          msg->set("event", "arp-reply");
          this->logger_->emit(msg);
        } else {
          reply = true;
        }
          
        free(buf);
      }

      if (this->logger_) {
        fluent::Message *msg = this->logger_->retain_message("lurker.arp-req");
        msg->set_ts(p.tv_sec());
        msg->set("src_addr", p.value("arp.src_pr").repr());
        msg->set("dst_addr", p.value("arp.dst_pr").repr());
        msg->set("src_hw", p.value("arp.src_hw").repr());
        msg->set("dst_hw", p.value("arp.dst_hw").repr());
        msg->set("replied", reply);
        this->logger_->emit(msg);
      }
    } 

  }
}

