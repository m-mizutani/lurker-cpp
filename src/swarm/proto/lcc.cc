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

  class LccDecoder : public Decoder {
  private:
    struct lcc_header {
      u_int16_t pkt_type_;
      u_int16_t addr_type_;
      u_int16_t addr_len_;
      u_int8_t addr_[8];
      u_int16_t proto_;
    } __attribute__((packed));

    ev_id EV_LCC_PKT_;
    val_id P_PROTO_;
    dec_id D_IPV4_;

  public:
    explicit LccDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_LCC_PKT_ = nd->assign_event ("lcc.packet",
                                            "Linux Cooked Capture Packet");
      this->P_PROTO_ = nd->assign_value ("lcc.proto", "Linux Cooked Capture");
    }
    void setup (NetDec * nd) {
      this->D_IPV4_ = nd->lookup_dec_id ("ipv4");
    };

    // Factory function for LccDecoder
    static Decoder * New (NetDec * nd) { return new LccDecoder (nd); }

    // Main decoding function.
    bool decode (Property *p) {
      auto lcc_hdr = reinterpret_cast <struct lcc_header *>
        (p->payload (sizeof (struct lcc_header)));

      if (lcc_hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_PROTO_, &(lcc_hdr->proto_), sizeof (lcc_hdr->proto_));

      // push event
      p->push_event (this->EV_LCC_PKT_);

      // call next decoder
      if (htons(lcc_hdr->proto_) == 0x800) {
        this->emit (this->D_IPV4_, p);
      }
      return true;
    }
  };

  INIT_DECODER (lcc, LccDecoder::New);
}  // namespace swarm
