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
#include "../debug.h"

namespace swarm {

  class Ipv6Decoder : public Decoder {
  private:
    static const size_t OCTET_UNIT = 8;

    static const u_int8_t PROTO_ICMP  = 1;
    static const u_int8_t PROTO_TCP   = 6;
    static const u_int8_t PROTO_UDP   = 17;
    static const u_int8_t PROTO_IPV6  = 41;
    static const u_int8_t PROTO_ICMP6 = 58;

    static const u_int8_t EXT_HBH   =  0;  // Hop-by-Hop Options
    static const u_int8_t EXT_DST   = 60;  // Destination Options
    static const u_int8_t EXT_ROURT = 43;  // Routing
    static const u_int8_t EXT_FRAG  = 44;  // Fragment
    static const u_int8_t EXT_AH    = 51;  // Authentication Header
    static const u_int8_t EXT_ESP   = 50;  // Encapsulating Security Payload
    static const u_int8_t EXT_MBL  = 135;  // Mobility

    struct ipv6_header {
      u_int32_t flags_;      // version, traffic class, flow label
      u_int16_t data_len_;   // dat length
      u_int8_t  next_hdr_;   // next header
      u_int8_t  hop_limit_;  // hop limit
      u_int32_t src_[4];     // source address
      u_int32_t dst_[4];     // dest address
    } __attribute__((packed));

    struct ipv6_option {
      u_int8_t next_hdr_;
      u_int8_t hdr_len_;
    } __attribute__((packed));

    ev_id EV_IPV6_PKT_;
    val_id P_PROTO_, P_SRC_, P_DST_, P_DLEN_, P_PL_;
    dec_id D_ICMP_;
    dec_id D_UDP_;
    dec_id D_TCP_;
    dec_id D_ICMP6_;

  public:
    DEF_REPR_CLASS (Proto, FacProto);

    explicit Ipv6Decoder (NetDec * nd) : Decoder (nd) {
      this->EV_IPV6_PKT_ = nd->assign_event ("ipv6.packet", "Ipv6 Packet");
      this->P_PROTO_ = nd->assign_value ("ipv6.proto", "Ipv6 Protocol",
                                         new FacProto ());
      this->P_SRC_   = nd->assign_value ("ipv6.src", "Ipv6 Source Address",
                                         new FacIPv6 ());
      this->P_DST_   = nd->assign_value ("ipv6.dst", "Ipv6 Destination Address",
                                         new FacIPv6 ());
      this->P_DLEN_  = nd->assign_value ("ipv6.data_len", "Ipv6 Data Length",
                                         new FacNum());
      this->P_PL_    = nd->assign_value ("ipv6.payload", "Ipv6 Data Payload");
    }
    void setup (NetDec * nd) {
      this->D_ICMP_  = nd->lookup_dec_id ("icmp");
      this->D_ICMP6_ = nd->lookup_dec_id ("icmp6");
      this->D_UDP_   = nd->lookup_dec_id ("udp");
      this->D_TCP_   = nd->lookup_dec_id ("tcp");
    };

    static Decoder * New (NetDec * nd) { return new Ipv6Decoder (nd); }

    bool next (u_int8_t next_hdr, Property *p) {
      // call next decoder
      switch (next_hdr) {
        // next protocol decoder
      case PROTO_ICMP:  this->emit (this->D_ICMP_,  p); break;
      case PROTO_TCP:   this->emit (this->D_TCP_,   p); break;
      case PROTO_UDP:   this->emit (this->D_UDP_,   p); break;
      case PROTO_ICMP6: this->emit (this->D_ICMP6_, p); break;

        // IPv6 extention header
      case EXT_HBH:
      case EXT_DST:
      case EXT_ROURT:
      case EXT_FRAG:
      case EXT_AH:
      case EXT_ESP:
      case EXT_MBL:
        {
          auto opthdr = reinterpret_cast <struct ipv6_option*>
            (p->payload (OCTET_UNIT));
          if (opthdr == nullptr) {
            return false;
          }

          if (opthdr->hdr_len_ > 0) {
            auto optdata = p->payload ((opthdr->hdr_len_) * OCTET_UNIT);
            if (optdata == nullptr) {
              return false;
            }
          }

          return this->next (opthdr->next_hdr_, p);
        }
        break;

      default:
        debug (0, "(%d) unknown", next_hdr);
      }

      return false;
    }

    bool decode (Property *p) {
      const size_t hdr_len = sizeof (struct ipv6_header);
      auto hdr = reinterpret_cast <struct ipv6_header *>
        (p->payload (hdr_len));

      if (hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_PROTO_, &(hdr->next_hdr_), sizeof (hdr->next_hdr_));
      p->set (this->P_SRC_,   &(hdr->src_), sizeof (hdr->src_));
      p->set (this->P_DST_,   &(hdr->dst_), sizeof (hdr->dst_));
      p->set (this->P_DLEN_,  &(hdr->data_len_), sizeof (hdr->data_len_));

      size_t data_len = htons (hdr->data_len_);
      auto ip_data = p->refer (data_len);
      if (ip_data) {
        p->set (this->P_PL_, ip_data, data_len);
      }

      // push event
      p->push_event (this->EV_IPV6_PKT_);

      // ToDo(masa): Reassembling IP fragmentation
      assert (sizeof (hdr->src_) == sizeof (hdr->dst_));
      p->set_addr (&(hdr->src_), &(hdr->dst_), hdr->next_hdr_,
                   sizeof (hdr->src_));

      return this->next (hdr->next_hdr_, p);
    }
  };

  std::string Ipv6Decoder::Proto::repr() const {
    std::string s;
    u_int8_t proto = this->ntoh <u_int8_t> ();
    switch (proto) {
    case PROTO_ICMP:  s = "ICMP";    break;
    case PROTO_TCP:   s = "TCP";     break;
    case PROTO_UDP:   s = "UDP";     break;
    case PROTO_IPV6:  s = "IPv6";    break;
    case PROTO_ICMP6: s = "ICMPv6";  break;
    default:          s = "unknown"; break;
    }
    return s;
  }

  INIT_DECODER (ipv6, Ipv6Decoder::New);
}  // namespace swarm
