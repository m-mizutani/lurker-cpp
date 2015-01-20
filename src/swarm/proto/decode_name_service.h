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

#ifndef SRC_PROTO_DECODE_NAME_SERVICE_H_
#define SRC_PROTO_DECODE_NAME_SERVICE_H_

#include <string>
#include "../swarm/decode.h"

namespace swarm {

  class NameServiceDecoder : public Decoder {
  private:
    struct ns_header {
      u_int16_t trans_id_;  // Transaction ID
      u_int16_t flags_;     // Flags
      u_int16_t qd_count_;  // Query Count
      u_int16_t an_count_;  // Answer Count
      u_int16_t ns_count_;  // Authory Count
      u_int16_t ar_count_;  // Additional Record Count
    } __attribute__((packed));

    struct ns_rr_header {
      u_int16_t type_;    // Resource type
      u_int16_t class_;   // Class (basically 0x0001)
    } __attribute__((packed));

    struct ns_ans_header {
      u_int32_t ttl_;     // Cache duration of resouce record
      u_int16_t rd_len_;  // Resource data length
    } __attribute__((packed));

    static const bool DEBUG = false;
    static const u_int16_t NS_FLAG_MASK_QUERY = 0x8000;
    static const u_int16_t RR_QD  = 0;
    static const u_int16_t RR_AN  = 1;
    static const u_int16_t RR_NS  = 2;
    static const u_int16_t RR_AR  = 3;
    static const u_int16_t RR_CNT = 4;

    // flags must be done ntohs ()
    inline static bool has_qr_flag (u_int16_t flags) {
      return ((flags & 0x0001) > 0);
    }

    inline static byte_t * parse_label (byte_t * p, size_t remain,
                                        const byte_t * sp,
                                        const size_t total_len,
                                        std::string * s);

    const std::string base_name_;
    ev_id EV_NS_PKT_, EV_TYPE_[4];
    val_id P_ID_;
    val_id P_QUERY_;
    val_id NS_NAME[4];
    val_id NS_TYPE[4];
    val_id NS_DATA[4];

  public:
    // VarNameServiceData for data part of record
    class VarNameServiceData : public Value {
    private:
      u_int16_t type_;
      byte_t * base_ptr_;
      size_t total_len_;

    public:
      std::string repr() const;
      void set_data (byte_t * ptr, size_t len, u_int16_t type,
                     byte_t * base_ptr, size_t total_len);
    };

    class FacNameServiceData : public ValueFactory {
    public:
      Value * New () { return new VarNameServiceData (); }
    };

    // VarNameServiceName for data part of record
    class VarNameServiceName : public Value {
    private:
      byte_t * base_ptr_;
      size_t total_len_;

    public:
      std::string repr () const;
      void set_data (byte_t * ptr, size_t len, byte_t * base_ptr,
                     size_t total_len);
    };
    class FacNameServiceName : public ValueFactory {
    public:
      Value * New () { return new VarNameServiceName (); }
    };


    DEF_REPR_CLASS (VarType, FacType);

    explicit NameServiceDecoder (NetDec * nd, const std::string &base_name);
    void setup (NetDec * nd);
    bool ns_decode (Property *p);
    bool decode (Property *p);
  };
}  // namespace swarm

#endif  // SRC_PROTO_DECODE_NAME_SERVICE_H_
