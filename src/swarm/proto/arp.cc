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

  class ArpDecoder : public Decoder {
  private:
    struct arp_header {
#define ARPHRD_ETHER           1  /* ethernet hardware format */
#define ARPHRD_IEEE802         6  /* token-ring hardware format */
#define ARPHRD_FRELAY         15  /* frame relay hardware format */
#define ARPHRD_IEEE1394       24  /* IEEE1394 hardware address */
#define ARPHRD_IEEE1394_EUI64 27  /* IEEE1394 EUI-64 */

#define ARPOP_REQUEST    1      /* request to resolve address */
#define ARPOP_REPLY      2      /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY   4      /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY   9      /* response identifying peer */

      u_int16_t hw_addr_fmt_;
      u_int16_t pr_addr_fmt_;
      u_int8_t  hw_addr_len_;
      u_int8_t  pr_addr_len_;
      u_int16_t op_;
    } __attribute__((packed));

    ev_id EV_ARP_PKT_, EV_REQ_, EV_REP_;
    val_id P_SRC_HW_, P_DST_HW_, P_SRC_PR_, P_DST_PR_, P_OP_;

  public:
    DEF_REPR_CLASS (VarPR, FacPR);
    DEF_REPR_CLASS (VarHW, FacHW);
    DEF_REPR_CLASS (VarOP, FacOP);

    explicit ArpDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_ARP_PKT_ = nd->assign_event ("arp.packet", "ARP Packet");
      this->EV_REQ_ = nd->assign_event ("arp.request", "ARP Request");
      this->EV_REP_ = nd->assign_event ("arp.reply", "ARP Reply");


      this->P_SRC_HW_ =
        nd->assign_value ("arp.src_hw", "Hardware Source Address",
                          new FacHW());
      this->P_SRC_PR_ =
        nd->assign_value ("arp.src_pr", "Protocol Source Address",
                          new FacPR());
      this->P_DST_HW_ =
        nd->assign_value ("arp.dst_hw", "Hardware Destination Address",
                          new FacHW ());
      this->P_DST_PR_ =
        nd->assign_value ("arp.dst_pr", "Protocol Destination Address",
                          new FacPR ());
      this->P_OP_ =
        nd->assign_value ("arp.op", "ARP Operation", new FacOP ());
    }
    void setup (NetDec * nd) {
      // nothing to do
    };

    static Decoder * New (NetDec * nd) { return new ArpDecoder (nd); }

    bool decode (Property *p) {
      auto arp_hdr = reinterpret_cast <struct arp_header *>
        (p->payload (sizeof (struct arp_header)));

      if (arp_hdr == nullptr) {
        return false;
      }

      p->set (this->P_OP_, &(arp_hdr->op_), sizeof (arp_hdr->op_));
      const size_t hw_len = static_cast <size_t> (arp_hdr->hw_addr_len_);
      const size_t pr_len = static_cast <size_t> (arp_hdr->pr_addr_len_);


      p->set (this->P_SRC_HW_, p->payload (hw_len), hw_len);
      p->set (this->P_SRC_PR_, p->payload (pr_len), pr_len);
      p->set (this->P_DST_HW_, p->payload (hw_len), hw_len);
      p->set (this->P_DST_PR_, p->payload (pr_len), pr_len);

      p->push_event (this->EV_ARP_PKT_);
      switch (ntohs (arp_hdr->op_)) {
      case ARPOP_REQUEST: p->push_event (this->EV_REQ_); break;
      case ARPOP_REPLY:   p->push_event (this->EV_REP_); break;
      }

      return true;
    }
  };

  std::string ArpDecoder::VarPR::repr() const {
    return this->ip4();
  }
  std::string ArpDecoder::VarHW::repr() const {
    return this->mac();
  }
  std::string ArpDecoder::VarOP::repr() const {
    u_int32_t op = this->uint32();
    std::string s;
    switch (op) {
    case ARPOP_REQUEST:    s = "REQUEST"; break;
    case ARPOP_REPLY:      s = "REPLY"; break;
    case ARPOP_REVREQUEST: s = "REVREQUEST"; break;
    case ARPOP_REVREPLY:   s = "REVREPLY"; break;
    case ARPOP_INVREQUEST: s = "INVREQUEST"; break;
    case ARPOP_INVREPLY:   s = "INVREPLY"; break;
    default:               s = "unknown"; break;
    }

    return s;
  }

  INIT_DECODER (arp, ArpDecoder::New);
}  // namespace swarm
