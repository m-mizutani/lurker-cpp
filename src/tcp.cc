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
#include <iostream>
#include <msgpack.hpp>

#include "./debug.h"
#include "./tcp.h"
#include "./pkt.h"

namespace lurker {
  // IP/TCP checksum calcurator
  uint16_t header_chksum(uint16_t *ptr, int nbytes) {
    uint32_t sum = 0;
    uint16_t oddbyte, answer;

    for (; nbytes > 1; nbytes -= 2) {
      sum += *ptr++;
    }

    if (nbytes == 1) {
      oddbyte = 0;
      *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
      sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    answer = ~sum;

    return answer;
  }

  TcpHandler::TcpHandler(swarm::Swarm *sw, TargetSet *target) :
    sw_(sw), sock_(NULL), target_(target), logger_(nullptr) {
    this->syn_ev_  = this->sw_->lookup_event_id("tcp.syn"); 
    this->data_ev_ = this->sw_->lookup_event_id("tcp_ssn.data"); 
    this->syn_hdlr_id_  = this->sw_->set_handler(this->syn_ev_, this); 
    this->data_hdlr_id_ = this->sw_->set_handler(this->data_ev_, this); 

    assert(this->syn_ev_ != swarm::EV_NULL);
    assert(this->data_ev_ != swarm::EV_NULL);
    assert(this->syn_hdlr_id_ != swarm::HDLR_NULL);
    assert(this->data_hdlr_id_ != swarm::HDLR_NULL);
  }
  TcpHandler::~TcpHandler() {
    this->sw_->unset_handler(this->syn_hdlr_id_);
    this->sw_->unset_handler(this->data_hdlr_id_);
  }

  void TcpHandler::set_sock(RawSock *sock) {
    this->sock_ = sock;
  }
  void TcpHandler::unset_sock() {
    this->sock_ = NULL;
  }

  void TcpHandler::set_logger(fluent::Logger *logger) {
    this->logger_ = logger;
  }
  

  size_t TcpHandler::build_tcp_synack_packet(const swarm::Property &p,
                                             void *data, size_t len) {
    // assign header
    const size_t pkt_len =
      sizeof(struct ether_header) + sizeof(struct ipv4_header) +
      sizeof(struct tcp_header);
    uint8_t *pkt = static_cast<uint8_t*> (malloc(pkt_len));
    auto *eth_hdr = reinterpret_cast<struct ether_header*>(pkt);
    auto *ipv4_hdr = reinterpret_cast<struct ipv4_header*>
      (pkt + sizeof(struct ether_header));
    auto *tcp_hdr = reinterpret_cast<struct tcp_header*>
      (pkt + sizeof(struct ether_header) + sizeof(struct ipv4_header));

    // build Ethernet header
    ::memcpy(eth_hdr->src_, p.value("ether.dst").ptr(), ETHER_ADDR_LEN);
    ::memcpy(eth_hdr->dst_, p.value("ether.src").ptr(), ETHER_ADDR_LEN);
    eth_hdr->type_ = htons(ETHERTYPE_IP);

    // build IPv4 header
    const uint16_t ipv4_tlen = sizeof(struct ipv4_header) + sizeof(struct tcp_header);

    void *ipv4_src = p.value("ipv4.src").ptr();
    void *ipv4_dst = p.value("ipv4.dst").ptr();
    ipv4_hdr->hdrlen_ = 5;
    ipv4_hdr->ver_ = 4;
    ipv4_hdr->tos_ = 0;
    ipv4_hdr->total_len_ = htons(ipv4_tlen);
    ipv4_hdr->id_ = rand();
    ipv4_hdr->offset_ = 0;
    ipv4_hdr->ttl_ = 64;
    ipv4_hdr->proto_ = IPPROTO_TCP;
    ipv4_hdr->chksum_ = 0; // should be set
    ::memcpy(&ipv4_hdr->src_, ipv4_dst, IPV4_ADDR_LEN);
    ::memcpy(&ipv4_hdr->dst_, ipv4_src, IPV4_ADDR_LEN);

    // build TCP header
    uint16_t sport = p.value("tcp.src_port").ntoh<uint16_t>();
    uint16_t dport = p.value("tcp.dst_port").ntoh<uint16_t>();

    tcp_hdr->src_port_ = htons(dport);
    tcp_hdr->dst_port_ = htons(sport);
    tcp_hdr->seq_ = random();
    tcp_hdr->ack_ = htonl(p.value("tcp.seq").uint32() + 1);
    tcp_hdr->offset_ = 0x5;
    tcp_hdr->x2_ = 0;
    tcp_hdr->flags_ = (TCP_SYN | TCP_ACK);
    tcp_hdr->window_ = htons(14480);
    tcp_hdr->chksum_ = 0;
    tcp_hdr->urgptr_ = 0;

    ipv4_hdr->chksum_ = header_chksum(reinterpret_cast<uint16_t*>(ipv4_hdr),
                                      sizeof(struct ipv4_header));

    uint8_t buf[1024];
    struct pseudo_ipv4_header *p_hdr =
      reinterpret_cast<struct pseudo_ipv4_header*>(buf);
    p_hdr->src_ = ipv4_hdr->src_;
    p_hdr->dst_ = ipv4_hdr->dst_;
    p_hdr->proto_ = IPPROTO_TCP;
    p_hdr->th_off_ = htons(sizeof(ipv4_header));
    p_hdr->x0_ = 0;

    ::memcpy(buf + sizeof(struct pseudo_ipv4_header), tcp_hdr,
             sizeof(struct tcp_header));
    tcp_hdr->chksum_ = header_chksum(reinterpret_cast<uint16_t*>(buf),
                                     sizeof(struct pseudo_ipv4_header) +
                                     sizeof(struct tcp_header));

    // Copy built packet data to buffer from argument.
    size_t rc = 0;
    if (pkt_len < len) {
      ::memcpy(data, pkt, pkt_len);
      rc = pkt_len;
    }

    free(pkt);
    return rc;
  }

  void TcpHandler::handle_synpkt(const swarm::Property &p) {
    if (this->target_->has(p.dst_addr(), p.dst_port())) {

      // Output to logger.
      if (this->logger_) {
        fluent::Message *msg = this->logger_->retain_message("lurker.tcp-syn");
        msg->set_ts(p.tv_sec());
        msg->set("src_addr", p.src_addr());
        msg->set("dst_addr", p.dst_addr());
        msg->set("src_port", p.src_port());
        msg->set("dst_port", p.dst_port());
        this->logger_->emit(msg);
      }

      if (this->sock_) {
        // activee mode
        size_t hw_len;
        void *hw_dst = p.value("ether.dst").ptr(&hw_len);

        if (p.value("ether.type").uint32() != ETHERTYPE_IP ||
            (0 != memcmp(hw_dst, this->sock_->hw_addr(), hw_len) &&
             hw_len == ETHER_ADDR_LEN)) {
          debug(DBG, "Invalid packet (ether-type=%d (should be %d), dst=%s, hw_len=%zd",
                p.value("ether.type").uint32(), ETHERTYPE_IP,
                p.value("ether.dst").repr().c_str(), hw_len);
        } 

        uint8_t buf[1024];
        size_t len = TcpHandler::build_tcp_synack_packet(p, buf, sizeof(buf));
        assert(len > 0);
        if (0 > this->sock_->write(buf, len)) {
          fluent::Message *msg = this->logger_->retain_message("lurker.error");
          msg->set("message", this->sock_->errmsg());
          this->logger_->emit(msg);
          
          // TODO: design how to handle error message appropriately.
          // std::ostream *os = (this->out_) ? this->out_ : &(std::cerr);
          // (*os) << this->sock_->errmsg() << std::endl;
        }
      }
    }
  }

  void TcpHandler::handle_data(const swarm::Property &p) {
    if (p.value("tcp_ssn.segment").is_null()) {
      debug(1, "data is null");
    } else {
      if (this->logger_) {
        size_t data_len;
        char *data_ptr = reinterpret_cast<char *>
          (p.value("tcp_ssn.segment").ptr(&data_len));
        std::string data(data_ptr, data_len);
        fluent::Message *msg = this->logger_->retain_message("lurker.tcp-data");
        msg->set("hash", p.hash_hex());
        msg->set("src_addr", p.src_addr());
        msg->set("dst_addr", p.dst_addr());
        msg->set("src_port", p.src_port());
        msg->set("dst_port", p.dst_port());
        msg->set("data", data);
        this->logger_->emit(msg);
      }
    }
  } 

  void TcpHandler::recv(swarm::ev_id eid, const swarm::Property &p) {
    if (eid == this->syn_ev_) {
      this->handle_synpkt(p);
    } else if (eid == this->data_ev_) {
      this->handle_data(p);
    }
  }
}

