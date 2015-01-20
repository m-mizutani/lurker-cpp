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


#include "../swarm/decode.h"

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK 0x9000
#endif
#ifndef ETHERTYPE_WLCCP /* Cisco Wireless LAN Context Control Protocol */
#define ETHERTYPE_WLCCP 0x872d
#endif
#ifndef ETHERTYPE_PPPOE_DISC
#define ETHERTYPE_PPPOE_DISC 0x8863
#endif
#ifndef ETHERTYPE_PPPOE_SSN
#define ETHERTYPE_PPPOE_SSN 0x8864
#endif
#ifndef ETHERTYPE_NETWARE /* Netware IPX/SPX */
#define ETHERTYPE_NETWARE 0x8137
#endif

namespace swarm {
  class EtherDecoder : public Decoder {
  private:
    static const size_t ETHER_ADDR_LEN = 6;

    struct ether_header {
      u_int8_t dst_[ETHER_ADDR_LEN];
      u_int8_t src_[ETHER_ADDR_LEN];
      u_int16_t type_;
    } __attribute__((packed));

    ev_id EV_ETH_PKT_;
    val_id P_SRC_, P_DST_, P_TYPE_, P_HDR_;
    dec_id D_ARP_, D_VLAN_, D_IPV4_, D_IPV6_, D_PPPOE_;

  public:
    explicit EtherDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_ETH_PKT_ = nd->assign_event ("ether.packet", "Ethernet Packet");
      this->P_SRC_ =
        nd->assign_value ("ether.src", "Ethernet Source MAC Address",
                          new FacMAC ());
      this->P_DST_ =
        nd->assign_value ("ether.dst", "Ethernet Destination MAC Address",
                          new FacMAC ());
      this->P_TYPE_ = nd->assign_value ("ether.type", "Ethernet Type");
      this->P_HDR_  = nd->assign_value ("ether.hdr", "Ethernet Header");
    }
    void setup (NetDec * nd) {
      this->D_ARP_  = nd->lookup_dec_id ("arp");
      this->D_VLAN_ = nd->lookup_dec_id ("vlan");
      this->D_IPV4_ = nd->lookup_dec_id ("ipv4");
      this->D_IPV6_ = nd->lookup_dec_id ("ipv6");
      this->D_PPPOE_ = nd->lookup_dec_id ("pppoe");
    };

    static Decoder * New (NetDec * nd) { return new EtherDecoder (nd); }

    bool decode (Property *p) {
      auto eth_hdr = reinterpret_cast <struct ether_header *>
        (p->payload (sizeof (struct ether_header)));

      if (eth_hdr == nullptr) {
        return false;
      }

      p->set (this->P_HDR_, eth_hdr, sizeof (struct ether_header));
      p->set (this->P_SRC_, eth_hdr->src_, sizeof (eth_hdr->src_));
      p->set (this->P_DST_, eth_hdr->dst_, sizeof (eth_hdr->dst_));
      p->set (this->P_TYPE_, &(eth_hdr->type_), sizeof (eth_hdr->type_));
      p->push_event (this->EV_ETH_PKT_);

      switch (ntohs (eth_hdr->type_)) {
      case ETHERTYPE_ARP:  this->emit (this->D_ARP_,  p); break;
      case ETHERTYPE_VLAN: this->emit (this->D_VLAN_, p); break;
      case ETHERTYPE_IP:   this->emit (this->D_IPV4_, p); break;
      case ETHERTYPE_IPV6: this->emit (this->D_IPV6_, p); break;
      case ETHERTYPE_PPPOE_SSN: this->emit (this->D_PPPOE_, p); break;
        // case ETHERTYPE_LOOPBACK: this->emit (this->D_IPV4_, p); break;
      }

      return true;
    }
  };

  INIT_DECODER (ether, EtherDecoder::New);
}  // namespace swarm
