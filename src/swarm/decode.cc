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

#include "./swarm/netdec.h"
#include "./swarm/decode.h"

namespace swarm {
  std::map <std::string, Decoder * (*)(NetDec *nd)>
  DecoderMap::protocol_decoder_map_ 
  __attribute__ ((init_priority (101)));


  DecoderMap::DecoderMap (const std::string &name,
                          Decoder * (*New) (NetDec * nd)) {
    DecoderMap::protocol_decoder_map_.insert (std::make_pair (name, New));
  }

  bool DecoderMap::reg_protocol_decoder (const std::string &name,
                                         Decoder * (*New) (NetDec * nd)) {
    DecoderMap::protocol_decoder_map_.insert (std::make_pair (name, New));
    return true;
  }

  size_t DecoderMap::build_decoder_vector (NetDec * nd,
                                           std::vector<Decoder *> *dec_vec,
                                           std::vector<std::string> *dec_name) {
    // TODO(masa): need to check contents of dec_vec, dec_name
    const size_t len = DecoderMap::protocol_decoder_map_.size ();
    size_t i = 0;
    dec_vec->resize (len);
    dec_name->resize (len);

    for (auto it = DecoderMap::protocol_decoder_map_.begin ();
         it != DecoderMap::protocol_decoder_map_.end (); it++, i++) {
      (*dec_name)[i] = it->first;
      (*dec_vec)[i] = (it->second) (nd);
    }

    return i;
  }

  // -------------------------------------------------------
  // Decoder
  void Decoder::emit (dec_id dec, Property *p) {
    if (dec != DEC_NULL) {
      this->nd_->decode (dec, p);
    }
  }
  bool Decoder::accept (const Property &p) {
    return false;
  }

  Decoder::Decoder (NetDec *nd) : nd_(nd) {
  }
  Decoder::~Decoder () {
  }
}  // namespace swarm
