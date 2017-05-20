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

#ifndef SRC_PKT_H__
#define SRC_PKT_H__

#include <sstream>

namespace lurker {

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
  static const u_int16_t ARPOP_REQUEST = 1; // request
  static const u_int16_t ARPOP_REPLY   = 2; // response to previous request 
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

  struct ipv4_header {
    // little endian mode
    u_int8_t  hdrlen_:4;
    u_int8_t  ver_:4;
    u_int8_t  tos_;
    u_int16_t total_len_;  /* total length */
    u_int16_t id_;
    u_int16_t offset_;     /* fragment offset */
    u_int8_t  ttl_;        /* Time To Live */
    u_int8_t  proto_;      /* L4 Protocol */
    u_int16_t chksum_;     /* ip header check sum */
    u_int32_t src_;        /* source ip address */
    u_int32_t dst_;        /* destination ip address */
  } __attribute__((packed));

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

  struct pseudo_ipv4_header {
    u_int32_t src_;        /* source ip address */
    u_int32_t dst_;        /* destination ip address */
    u_int8_t x0_;
    u_int8_t proto_;
    u_int16_t th_off_;
  } __attribute__((packed));

  struct tcp_header {
    u_int16_t src_port_;  // source port
    u_int16_t dst_port_;  // destination port
    u_int32_t seq_;       // tcp sequence number
    u_int32_t ack_;       // tcp ack number

    // ToDo(Masa): 4 bit data field should be updated for little-endian
    u_int8_t x2_:4, offset_:4;

    u_int8_t flags_;      // flags
    u_int16_t window_;    // window
    u_int16_t chksum_;    // checksum
    u_int16_t urgptr_;    // urgent pointer
  } __attribute__((packed));  
}


#endif  // SRC_PKT_H__
