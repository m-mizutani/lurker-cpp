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

#include "../external/packetmachine/src/packetmachine.hpp"
#include "../external/libfluent/src/fluent.hpp"
#include "./debug.h"
#include "./spoof.hpp"
#include "./pkt.hpp"
#include "./rawsock.hpp"

namespace lurker {

Spoofer::Spoofer(pm::Machine *machine, fluent::Logger *logger) :
    machine_(machine), sock_(nullptr), logger_(logger) {
  /*
  assert(this->sw_);
  this->req_h_ = this->sw_->set_handler("arp.request", this);
  this->rep_h_ = this->sw_->set_handler("arp.reply",   this);
  this->req_id_ = this->sw_->lookup_event_id("arp.request");
  this->rep_id_ = this->sw_->lookup_event_id("arp.reply");
  */
}
Spoofer::~Spoofer() {
}
/*

// Routing to callback function.
void Spoofer::recv(swarm::ev_id eid, const  swarm::Property &p) {
  if (eid == this->req_id_) {
    this->handle_arp_request(p);
  }
  if (eid == this->rep_id_) {
    this->handle_arp_reply(p);
  }
}

bool Spoofer::write(uint8_t *buf, size_t buf_len,
                    const std::string &ev_name) {
  bool rc = false;

  if (this->sock_) {
    if (this->sock_->write(buf, buf_len) < 0) {
      if (this->logger_) {
        fluent::Message *msg =
            this->logger_->retain_message("lurker.error");
        msg->set("event", ev_name);
        msg->set("message", this->sock_->errmsg());
        this->logger_->emit(msg);
      }
    } else {
      rc = true;
    }
  }

  return rc;
}

uint8_t* Spoofer::build_arp_request(void *addr, size_t *len) {
  const uint8_t *hw_addr =  this->sock_hw_addr();
  const uint8_t *pr_addr =  this->sock_pr_addr();
  assert(hw_addr);

  if (pr_addr) {
    // Can not send ARP request if the interface has no IP address.
    size_t buf_len =
        sizeof(struct ether_header) + sizeof(struct arp_header);
    uint8_t *buf = reinterpret_cast<uint8_t *>(malloc(buf_len));

    struct ether_header *eth_hdr
        = reinterpret_cast<struct ether_header*>(buf);
    struct arp_header *arp_hdr
        = reinterpret_cast<struct arp_header*>(buf +
                                               sizeof(struct ether_header));
    memset(eth_hdr->dst_, ~0, ETHER_ADDR_LEN);
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++) {
      printf("[%d] = 0x%02X\n", eth_hdr->dst_[i]);
    }
    eth_hdr->type_ = htons(ETHERTYPE_ARP);

    arp_hdr->hw_addr_fmt_ = htons(ARPHRD_ETHER);
    arp_hdr->pr_addr_fmt_ = htons(ETHERTYPE_IP);
    arp_hdr->hw_addr_len_ = IPV4_ADDR_LEN;
    arp_hdr->pr_addr_len_ = ETHER_ADDR_LEN;
    arp_hdr->op_ = htons(ARPOP_REQUEST);

    const size_t pr_len = IPV4_ADDR_LEN;
    const size_t hw_len = ETHER_ADDR_LEN;

    memcpy(arp_hdr->src_hw_addr_, hw_addr, hw_len);
    memcpy(arp_hdr->src_pr_addr_, pr_addr, pr_len);
    memset(arp_hdr->dst_hw_addr_, 0, hw_len);
    memcpy(arp_hdr->dst_pr_addr_, addr, pr_len);

    *len = buf_len;
    return buf;
  } else {
    return nullptr;
  }
}

uint8_t* Spoofer::build_arp_reply(const swarm::Property &p, size_t *len) {
  size_t buf_len = sizeof(struct ether_header) + sizeof(struct arp_header);
  uint8_t *buf = reinterpret_cast<uint8_t *>(malloc(buf_len));

  struct ether_header *eth_hdr
      = reinterpret_cast<struct ether_header*>(buf);
  struct arp_header *arp_hdr
      = reinterpret_cast<struct arp_header*>(buf +
                                             sizeof(struct ether_header));

  memcpy(eth_hdr->dst_, p.value("ether.src").ptr(), ETHER_ADDR_LEN);
  eth_hdr->type_ = htons(ETHERTYPE_ARP);

  arp_hdr->hw_addr_fmt_ = htons(ARPHRD_ETHER);
  arp_hdr->pr_addr_fmt_ = htons(ETHERTYPE_IP);
  arp_hdr->hw_addr_len_ = 6;
  arp_hdr->pr_addr_len_ = 4;
  arp_hdr->op_ = htons(ARPOP_REPLY);

  const size_t pr_len = IPV4_ADDR_LEN;
  const size_t hw_len = ETHER_ADDR_LEN;

  memcpy(arp_hdr->src_hw_addr_, this->sock_hw_addr(), hw_len);
  memcpy(arp_hdr->src_pr_addr_, p.value("arp.dst_pr").ptr(), pr_len);
  memcpy(arp_hdr->dst_hw_addr_, p.value("arp.src_hw").ptr(), hw_len);
  memcpy(arp_hdr->dst_pr_addr_, p.value("arp.src_pr").ptr(), pr_len);

  *len = buf_len;
  return buf;
}


void Spoofer::free_arp_reply(uint8_t *ptr) {
  free(ptr);
}

void Spoofer::free_arp_request(uint8_t *ptr) {
  free(ptr);
}


StaticSpoofer::StaticSpoofer(swarm::Swarm *sw, TargetSet *target_set,
                             fluent::Logger *logger, RawSock *sock) :
    Spoofer(sw, logger, sock), target_set_(target_set) {
}
StaticSpoofer::~StaticSpoofer() {
}
void StaticSpoofer::handle_arp_request(const swarm::Property &p) {
  bool replied = false;
  size_t addr_len;
  void *dst_addr = p.value("arp.dst_pr").ptr(&addr_len);
  const void *sock_addr = this->sock_pr_addr();
  if (this->target_set_->has(p.value("arp.dst_pr").repr()) &&
      this->has_sock() &&
      (sock_addr == nullptr ||
       0 != memcmp(dst_addr, sock_addr , addr_len))) {
    size_t buf_len;
    uint8_t* buf = build_arp_reply(p, &buf_len);
    replied =  this->write(buf, buf_len, "arp-reply");
    free_arp_reply(buf);
  }

  if (this->logger_) {
    fluent::Message *msg = this->logger_->retain_message("lurker.arp_req");
    msg->set_ts(p.tv_sec());
    msg->set("src_addr", p.value("arp.src_pr").repr());
    msg->set("dst_addr", p.value("arp.dst_pr").repr());
    msg->set("src_hw", p.value("arp.src_hw").repr());
    msg->set("dst_hw", p.value("arp.dst_hw").repr());
    msg->set("replied", replied);
    this->logger_->emit(msg);
  }
}
void StaticSpoofer::handle_arp_reply(const swarm::Property &p) {
  // Nothing to do.
}


DynamicSpoofer::DynamicSpoofer(swarm::Swarm *sw, fluent::Logger *logger,
                               RawSock *sock) :
    Spoofer(sw, logger, sock) {
}
DynamicSpoofer::~DynamicSpoofer() {
}

void DynamicSpoofer::handle_arp_request(const swarm::Property &p) {
  const std::string &src_addr = p.value("arp.src_pr").repr();
  const std::string &dst_addr = p.value("arp.dst_pr").repr();

  // Remove source address from target address set.
  if (this->disg_addrs_.find(src_addr) != this->disg_addrs_.end()) {
    debug(true, "remove: %s", src_addr.c_str());
    this->disg_addrs_.erase(src_addr);
    return;
  }

  // Reply if the address is target.
  const time_t timeout = 5;
  auto it = this->disg_addrs_.find(dst_addr);
  if (it != this->disg_addrs_.end() &&
      it->second + timeout > p.tv_sec()) {

    bool replied = false;
    if (this->has_sock()) {
      size_t buf_len;
      uint8_t* buf = build_arp_reply(p, &buf_len);
      replied =  this->write(buf, buf_len, "arp-reply");
      free_arp_reply(buf);
    }

    fluent::Message *msg = this->logger_->retain_message("lurker.arp_req");
    msg->set_ts(p.tv_sec());
    msg->set("src_addr", p.value("arp.src_pr").repr());
    msg->set("dst_addr", p.value("arp.dst_pr").repr());
    msg->set("src_hw", p.value("arp.src_hw").repr());
    msg->set("dst_hw", p.value("arp.dst_hw").repr());
    msg->set("replied", replied);
    this->logger_->emit(msg);

  } else if (src_addr != dst_addr) {
    // If not Gratuitous ARP, register the address and timestamp.
    size_t buf_len;
    uint8_t* buf = build_arp_request(p.value("arp.dst_pr").ptr(),
                                     &buf_len);
    if (buf) {
      if (this->write(buf, buf_len, "arp-request")) {
        // Register the IP address and timestamp if request is sent.
        this->disg_addrs_.insert(std::make_pair(dst_addr, p.tv_sec()));
        debug(true, "add: %s", dst_addr.c_str());
      }
      free_arp_request(buf);
    }
  }
}

void DynamicSpoofer::handle_arp_reply(const swarm::Property &p) {
  const uint8_t *hw_addr =  this->sock_hw_addr();
  assert(hw_addr);

  if (memcmp(p.value("arp.src_hw").ptr(), hw_addr, ETHER_ADDR_LEN) != 0) {
    // Ignore arp reply from ownself.
    const std::string &src_addr = p.value("arp.src_pr").repr();

    // Remove source address from target address set.
    if (this->disg_addrs_.find(src_addr) != this->disg_addrs_.end()) {
      debug(true, "remove: %s", src_addr.c_str());
      this->disg_addrs_.erase(src_addr);
    }
  }
}

*/

}
