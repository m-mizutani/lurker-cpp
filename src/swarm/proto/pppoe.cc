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

  class PppoeDecoder : public Decoder {
  private:
    struct pppoe_header {
      u_int8_t ver_;
      u_int8_t code_;
      u_int16_t session_id_;
      u_int16_t length_;
    } __attribute__((packed));

    ev_id EV_PPPOE_PKT_;
    val_id P_VER_, P_TYPE_, P_CODE_, P_SSN_ID_;
    val_id P_ETH_TYPE_;
    dec_id D_IPV4_;

  public:
    // Factory function for PppoeDecoder
    static Decoder * New (NetDec * nd) { return new PppoeDecoder (nd); }

    explicit PppoeDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_PPPOE_PKT_ = nd->assign_event ("pppoe.packet",
                                              "PPP over Ether Packet");
      this->P_VER_  = nd->assign_value ("pppoe.ver",  "PPPoE version");
      this->P_TYPE_ = nd->assign_value ("pppoe.type", "PPPoE type");
      this->P_CODE_ = nd->assign_value ("pppoe.code", "PPPoE code");
      this->P_SSN_ID_ = nd->assign_value ("pppoe.ssn_id", "PPPoE session ID");
    }
    void setup (NetDec * nd) {
      this->D_IPV4_ = nd->lookup_dec_id ("ipv4");
      this->P_ETH_TYPE_ = nd->lookup_value_id ("ether.type");
    };

    // Main decoding function.
    bool decode (Property *p) {
      auto pppoe_hdr = reinterpret_cast <struct pppoe_header *>
        (p->payload (sizeof (struct pppoe_header)));

      if (pppoe_hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_CODE_, &(pppoe_hdr->code_), sizeof (pppoe_hdr->code_));
      p->set (this->P_SSN_ID_, &(pppoe_hdr->session_id_),
              sizeof (pppoe_hdr->session_id_));

      // push event
      p->push_event (this->EV_PPPOE_PKT_);

      // call next decoder
      
      if (p->value(this->P_ETH_TYPE_).ntoh <u_int16_t>() == 0x8864) {
        u_int16_t *proto = reinterpret_cast<u_int16_t*>(p->payload(sizeof(u_int16_t)));
        if (htons(*proto) == 0x0021) {
          this->emit (this->D_IPV4_, p);
        }
      }
      return true;
    }
  };

  INIT_DECODER (pppoe, PppoeDecoder::New);
}  // namespace swarm
