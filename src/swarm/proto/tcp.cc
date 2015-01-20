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

#include <sstream>
#include "./debug.h"
#include "../swarm/decode.h"


namespace swarm {

  class TcpDecoder : public Decoder {
  private:
    struct tcp_header {
      u_int16_t src_port_;  // source port
      u_int16_t dst_port_;  // destination port
      u_int32_t seq_;       // tcp sequence number
      u_int32_t ack_;       // tcp ack number

      // ToDo(Masa): 4 bit data field should be updated for little-endian
      u_int8_t offset_;

      u_int8_t flags_;      // flags
      u_int16_t window_;    // window
      u_int16_t chksum_;    // checksum
      u_int16_t urgptr_;    // urgent pointer
    } __attribute__((packed));

    static const u_int8_t FIN  = 0x01;
    static const u_int8_t SYN  = 0x02;
    static const u_int8_t RST  = 0x04;
    static const u_int8_t PUSH = 0x08;
    static const u_int8_t ACK  = 0x10;
    static const u_int8_t URG  = 0x20;
    static const u_int8_t ECE  = 0x40;
    static const u_int8_t CWR  = 0x80;

    ev_id EV_PKT_, EV_SYN_;
    val_id P_SRC_PORT_, P_DST_PORT_, P_FLAGS_, P_SEQ_, P_ACK_;
    dec_id TCP_SSN_;

  public:
    DEF_REPR_CLASS (VarFlags, FacFlags);

    explicit TcpDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_PKT_ = nd->assign_event ("tcp.packet", "TCP Packet");
      this->EV_SYN_ = nd->assign_event ("tcp.syn", "TCP SYN Packet");

      this->P_SRC_PORT_ =
        nd->assign_value ("tcp.src_port", "TCP Source Port",
                          new FacNum ());
      this->P_DST_PORT_ =
        nd->assign_value ("tcp.dst_port", "TCP Destination Port",
                          new FacNum ());
      this->P_FLAGS_ =
        nd->assign_value ("tcp.flags", "TCP Flags", new FacFlags ());
      this->P_SEQ_ = nd->assign_value ("tcp.seq", "TCP Sequence Number");
      this->P_ACK_ = nd->assign_value ("tcp.ack", "TCP Acknowledge");

    }
    void setup (NetDec * nd) {
      this->TCP_SSN_ = nd->lookup_dec_id("tcp_ssn");
    };

    static Decoder * New (NetDec * nd) { return new TcpDecoder (nd); }

    bool decode (Property *p) {
      auto hdr = reinterpret_cast <struct tcp_header *>
        (p->payload (sizeof (struct tcp_header)));

      if (hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_SRC_PORT_, &(hdr->src_port_), sizeof (hdr->src_port_));
      p->set (this->P_DST_PORT_, &(hdr->dst_port_), sizeof (hdr->dst_port_));
      p->set (this->P_FLAGS_,    &(hdr->flags_),    sizeof (hdr->flags_));
      p->set (this->P_SEQ_,      &(hdr->seq_),      sizeof (hdr->seq_));
      p->set (this->P_ACK_,      &(hdr->ack_),      sizeof (hdr->ack_));

      // push event
      p->push_event (this->EV_PKT_);

      assert (sizeof (hdr->src_port_) == sizeof (hdr->dst_port_));
      p->set_port (&(hdr->src_port_), &(hdr->dst_port_),
                   sizeof (hdr->src_port_));

      if ((hdr->flags_ & (SYN | ACK)) == SYN) {
        p->push_event (this->EV_SYN_);
      }

      p->calc_hash();

      // TCP Header Option handling
      size_t hdr_len = ((hdr->offset_ & 0xf0) >> 2);
      if (hdr_len < sizeof(struct tcp_header)) {
        return false;
      }

      size_t opthdr_len = hdr_len - sizeof(struct tcp_header);
      // debug(true, "hdr:%zd, opt:%zd", hdr_len, opthdr_len);
      assert(opthdr_len < 0xfff);

      if (opthdr_len > 0) {
        byte_t *opt = p->payload(opthdr_len);
        if (!opt) {
          // debug(true, "invalid option length");
          return false;
        }
        size_t optlen = 0;
        for (byte_t *op = opt; op + 2 < opt + opthdr_len; op += optlen) {
          if (op[0] == 1) {
            optlen = 1;
            continue;
          }

          if (op + 2 >= opt + opthdr_len) {
            break;
          }
          // debug(1, "kind:%zd, len:%zd", op[0], op[1]);
          optlen = op[1];

          if (optlen == 0) {
            return false;
          }
        }
      }

      this->emit(this->TCP_SSN_, p);

      return true;
    }
  };

  std::string TcpDecoder::VarFlags::repr () const {
    std::stringstream ss;
    u_int8_t *flags = this->ptr();
    ss << ((*flags & FIN) > 0 ? "F" : "*");
    ss << ((*flags & SYN) > 0 ? "S" : "*");
    ss << ((*flags & RST) > 0 ? "R" : "*");
    ss << ((*flags & PUSH) > 0 ? "P" : "*");
    ss << ((*flags & ACK) > 0 ? "A" : "*");
    ss << ((*flags & URG) > 0 ? "U" : "*");
    ss << ((*flags & ECE) > 0 ? "E" : "*");
    ss << ((*flags & CWR) > 0 ? "C" : "*");
    return ss.str();
  }

  INIT_DECODER (tcp, TcpDecoder::New);
}  // namespace swarm
