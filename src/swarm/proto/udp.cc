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


namespace swarm {

  class UdpDecoder : public Decoder {
  private:
    struct udp_header {
      u_int16_t src_port_;  // source port
      u_int16_t dst_port_;  // destination port
      u_int16_t length_;    // length
      u_int16_t chksum_;    // checksum
    } __attribute__((packed));

    ev_id EV_UDP_PKT_;
    val_id P_SRC_PORT_, P_DST_PORT_, P_LEN_;
    dec_id D_DNS_, D_LLMNR_, D_NETBIOS_NS_, D_MDNS_;

  public:
    explicit UdpDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_UDP_PKT_ = nd->assign_event ("udp.packet", "UDP Packet");

      this->P_SRC_PORT_ =
        nd->assign_value ("udp.src_port", "UDP Source Port",
                          new FacNum ());
      this->P_DST_PORT_ =
        nd->assign_value ("udp.dst_port", "UDP Destination Port",
                          new FacNum ());
      this->P_LEN_ =
        nd->assign_value ("udp.len", "UDP Data Length", new FacNum ());
    }
    void setup (NetDec * nd) {
      this->D_DNS_ = nd->lookup_dec_id ("dns");
      this->D_LLMNR_ = nd->lookup_dec_id ("llmnr");
      this->D_NETBIOS_NS_ = nd->lookup_dec_id ("netbios_ns");
      this->D_MDNS_ = nd->lookup_dec_id ("mdns");
    };

    static Decoder * New (NetDec * nd) { return new UdpDecoder (nd); }

    bool decode (Property *p) {
      auto hdr = reinterpret_cast <struct udp_header *>
        (p->payload (sizeof (struct udp_header)));

      if (hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_SRC_PORT_, &(hdr->src_port_), sizeof (hdr->src_port_));
      p->set (this->P_DST_PORT_, &(hdr->dst_port_), sizeof (hdr->dst_port_));
      p->set (this->P_LEN_, &(hdr->length_), sizeof (hdr->length_));

      // push event
      p->push_event (this->EV_UDP_PKT_);

      // set basic property (UDP port)
      assert (sizeof (hdr->src_port_) == sizeof (hdr->dst_port_));
      p->set_port (&(hdr->src_port_), &(hdr->dst_port_),
                   sizeof (hdr->src_port_));
      p->calc_hash();

      // call next decoder
      if (ntohs (hdr->src_port_) == 53 ||
          ntohs (hdr->dst_port_) == 53) {
        this->emit (this->D_DNS_, p);
      } else if (ntohs (hdr->src_port_) == 5355 ||
                 ntohs (hdr->dst_port_) == 5355) {
        this->emit (this->D_LLMNR_, p);
      } else if (ntohs (hdr->src_port_) == 137 ||
                 ntohs (hdr->dst_port_) == 137) {
        this->emit (this->D_NETBIOS_NS_, p);
      } else if (ntohs (hdr->src_port_) == 5353 ||
                 ntohs (hdr->dst_port_) == 5353) {
        this->emit (this->D_MDNS_, p);
      }

      return true;
    }
  };

  INIT_DECODER (udp, UdpDecoder::New);
}  // namespace swarm
