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

  class SampleDecoder : public Decoder {
  private:
    struct sample_header {
      u_int16_t op_;
    } __attribute__((packed));

    ev_id EV_SAMPLE_PKT_;
    val_id P_OP_;
    dec_id D_NEXT_;

  public:
    // DEF_REPR_CLASS defines a class extended by Var for repr() as
    // representation. 1st argument is an extended class, and 2nd is
    // a factory class. In SampleDecoder::VarSample (), you can provide
    // original representation logic for special data type.
    //
    DEF_REPR_CLASS (VarSample, FacSample);

    explicit SampleDecoder (NetDec * nd) : Decoder (nd) {
      // assign_event () can assign name of event for the decoder.
      // One of recommended events is a packet arrival
      // such as "ether.packet" meaning an ethernet packet arrives
      //
      this->EV_SAMPLE_PKT_ = nd->assign_event ("sample.packet",
                                               "Sample Packet");

      // assign_param () can assign name of parameter for the decoder
      // and FactoryClass can be registered if you need.
      //
      this->P_OP_  = nd->assign_value ("sample.op", "Just Sample",
                                       new FacSample ());
    }
    void setup (NetDec * nd) {
      // In setup(), you should obtatin decoder ID of other decoder
      // by lookup_dec_id (). You can obtain the IDs in decode (), however
      // it's not good from performance view point.
      //
      this->D_NEXT_ = nd->lookup_dec_id ("next");
    };

    // Factory function for SampleDecoder
    static Decoder * New (NetDec * nd) { return new SampleDecoder (nd); }

    // Main decoding function.
    bool decode (Property *p) {
      auto sample_hdr = reinterpret_cast <struct sample_header *>
        (p->payload (sizeof (struct sample_header)));

      if (sample_hdr == nullptr) {
        return false;
      }

      // set data to property
      p->set (this->P_OP_, &(sample_hdr->op_), sizeof (sample_hdr->op_));

      // push event
      p->push_event (this->EV_SAMPLE_PKT_);

      // call next decoder
      this->emit (this->D_NEXT_, p);

      return true;
    }
  };

  std::string SampleDecoder::VarSample::repr() const {
    return this->ip4();
  }

  INIT_DECODER (sample, SampleDecoder::New);
}  // namespace swarm
