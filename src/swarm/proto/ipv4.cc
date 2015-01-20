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

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */


namespace swarm {

  class IPv4Decoder : public Decoder {
  private:
    static const u_int8_t PROTO_ICMP  = 1;
    static const u_int8_t PROTO_TCP   = 6;
    static const u_int8_t PROTO_UDP   = 17;
    static const u_int8_t PROTO_IPV6  = 41;
    static const u_int8_t PROTO_ICMP6 = 58;

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

    ev_id EV_IPV4_PKT_;
    val_id P_PROTO_, P_SRC_, P_DST_, P_TLEN_, P_PL_;
    dec_id D_ICMP_;
    dec_id D_UDP_;
    dec_id D_TCP_;
    dec_id D_ICMP6_;

  public:
    DEF_REPR_CLASS (Proto, FacProto);

    explicit IPv4Decoder (NetDec * nd) : Decoder (nd) {
      this->EV_IPV4_PKT_ = nd->assign_event ("ipv4.packet", "IPv4 Packet");
      this->P_PROTO_ = nd->assign_value ("ipv4.proto", "IPv4 Protocol",
                                         new FacProto ());
      this->P_SRC_   = nd->assign_value ("ipv4.src", "IPv4 Source Address",
                                         new FacIPv4 ());
      this->P_DST_   = nd->assign_value ("ipv4.dst", "IPv4 Destination Address",
                                         new FacIPv4 ());
      this->P_TLEN_  = nd->assign_value ("ipv4.total", "IPv4 Total Length",
                                         new FacNum());
      this->P_PL_    = nd->assign_value ("ipv4.payload", "IPv4 Data Payload");
    }
    void setup (NetDec * nd) {
      this->D_ICMP_  = nd->lookup_dec_id ("icmp");
      this->D_ICMP6_ = nd->lookup_dec_id ("icmp6");
      this->D_UDP_   = nd->lookup_dec_id ("udp");
      this->D_TCP_   = nd->lookup_dec_id ("tcp");
    };

    static Decoder * New (NetDec * nd) { return new IPv4Decoder (nd); }

    bool decode (Property *p) {
      const size_t base_len = sizeof (struct ipv4_header);
      auto hdr = reinterpret_cast <struct ipv4_header *>
        (p->payload (base_len));

      if (hdr == nullptr) {
        return false;
      }

      const size_t hdr_len = hdr->hdrlen_ << 2;

      // set data to property
      p->set (this->P_PROTO_, &(hdr->proto_), sizeof (hdr->proto_));
      p->set (this->P_SRC_,   &(hdr->src_), sizeof (hdr->src_));
      p->set (this->P_DST_,   &(hdr->dst_), sizeof (hdr->dst_));
      p->set (this->P_TLEN_,  &(hdr->total_len_), sizeof (hdr->total_len_));

      // just moving to next protocol header
      auto opt = p->payload (hdr_len - base_len);
      if (!opt) {
        // not enough length for IP options
        return false;
      }

      size_t data_len = htons (hdr->total_len_) - (hdr_len);
      auto ip_data = p->refer (data_len);
      if (ip_data) {
        p->set (this->P_PL_, ip_data, data_len);
      }

      // push event
      p->push_event (this->EV_IPV4_PKT_);

      // ToDo(masa): Reassembling IP fragmentation
      assert (sizeof (hdr->src_) == sizeof (hdr->dst_));
      p->set_addr (&(hdr->src_), &(hdr->dst_), hdr->proto_, sizeof (hdr->src_));

      // call next decoder
      switch (hdr->proto_) {
      case PROTO_ICMP:  this->emit (this->D_ICMP_,  p); break;
      case PROTO_TCP:   this->emit (this->D_TCP_,   p); break;
      case PROTO_UDP:   this->emit (this->D_UDP_,   p); break;
      case PROTO_ICMP6: this->emit (this->D_ICMP6_, p); break;
      }

      return true;
    }
  };

  std::string IPv4Decoder::Proto::repr() const {
    u_int32_t proto = this->uint32 ();
    std::string s;
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

  INIT_DECODER (ipv4, IPv4Decoder::New);
}  // namespace swarm
