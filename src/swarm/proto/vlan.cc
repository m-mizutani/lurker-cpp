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

  class VlanDecoder : public Decoder {
  private:
    struct vlan_header {
      u_int16_t tci_;          // Encapsulates priority and VLAN ID
      u_int16_t encap_proto_;  // Encapsulated Protocol ID or Len
    } __attribute__((packed));

    ev_id EV_VLAN_PKT_;
    val_id P_PROTO_, P_ID_;
    dec_id D_ARP_, D_VLAN_, D_IPV4_, D_IPV6_;

    static const u_int16_t ETHERTYPE_ARP = 0x0806;
    static const u_int16_t ETHERTYPE_VLAN = 0x8100;
    static const u_int16_t ETHERTYPE_IP = 0x0800;
    static const u_int16_t ETHERTYPE_IPV6 = 0x86dd;
    static const u_int16_t ETHERTYPE_LOOPBACK = 0x9000;
    static const u_int16_t ETHERTYPE_WLCCP = 0x872d;
    static const u_int16_t ETHERTYPE_NETWARE = 0x8137;

  public:
    // DEF_REPR_CLASS defines a class extended by Var for repr() as
    // representation. 1st argument is an extended class, and 2nd is
    // a factory class. In VlanDecoder::VarVlan (), you can provide
    // original representation logic for special data type.
    //
    DEF_REPR_CLASS (VarVlanProto, FacVlanProto);

    explicit VlanDecoder (NetDec * nd) : Decoder (nd) {
      // assign_event () can assign name of event for the decoder.
      // One of recommended events is a packet arrival
      // such as "ether.packet" meaning an ethernet packet arrives
      //
      this->EV_VLAN_PKT_ = nd->assign_event ("vlan.packet",
                                               "Vlan Packet");

      this->P_PROTO_  =
        nd->assign_value ("vlan.proto", "VLAN Encaped Protocol",
                          new FacVlanProto ());
      this->P_ID_  =
        nd->assign_value ("vlan.id", "VLAN ID");
    }
    void setup (NetDec * nd) {
      this->D_ARP_  = nd->lookup_dec_id ("arp");
      this->D_IPV4_ = nd->lookup_dec_id ("ipv4");
      this->D_IPV6_ = nd->lookup_dec_id ("ipv6");
    };

    // Factory function for VlanDecoder
    static Decoder * New (NetDec * nd) { return new VlanDecoder (nd); }

    // Main decoding function.
    bool decode (Property *p) {
      auto hdr = reinterpret_cast <struct vlan_header *>
        (p->payload (sizeof (struct vlan_header)));

      if (hdr == nullptr) {
        return false;
      }

      u_int16_t vlan_id = ntohs (hdr->tci_) & 0x7f;
      vlan_id = htons (vlan_id);
      p->copy (this->P_ID_, &vlan_id, sizeof (vlan_id));
      p->set (this->P_PROTO_, &(hdr->encap_proto_),
              sizeof (hdr->encap_proto_));;

      // push event
      p->push_event (this->EV_VLAN_PKT_);

      // emit to a upper layer decoder
      switch (ntohs (hdr->encap_proto_)) {
      case ETHERTYPE_ARP:  this->emit (this->D_ARP_,  p); break;
      case ETHERTYPE_VLAN: this->emit (this->D_VLAN_, p); break;
      case ETHERTYPE_IP:   this->emit (this->D_IPV4_, p); break;
      case ETHERTYPE_IPV6: this->emit (this->D_IPV6_, p); break;
      case ETHERTYPE_LOOPBACK: break;  // ignore
      case ETHERTYPE_WLCCP:    break;  // ignore
      case ETHERTYPE_NETWARE:  break;  // ignore
      }

      return true;
    }
  };

  std::string VlanDecoder::VarVlanProto::repr () const {
    return this->ip4();
  }

  INIT_DECODER (vlan, VlanDecoder::New);
}  // namespace swarm
