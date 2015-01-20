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
#include "./decode_name_service.h"
#include "./debug.h"

namespace swarm {
  std::string NameServiceDecoder::VarNameServiceData::repr() const {
    std::string s;

    size_t r_len;
    byte_t * r_ptr = this->ptr(&r_len);

    bool rc = false;
    switch (this->type_) {
    case  1: s = this->ip4(); break;  // A
    case 28: s = this->ip6(); break;  // AAAA
    case  2:  // NS
    case  5:  // CNAME
    case  6:  // SOA
    case 12:  // PTR
    case 15:  // MX
      {
        size_t len;
        byte_t * ptr = this->ptr(&len);
        byte_t * rp
          = NameServiceDecoder::parse_label (ptr, len, this->base_ptr_,
                                             this->total_len_, &s);
        if (rp == NULL) {
          s = Value::null_;
        }
      }
      break;

    case 16: // TXT
      {
        std::stringstream ss;
        size_t len, d_len;
        byte_t * start_ptr = this->ptr(&len);
        debug(0, "len = %zd", len);
        for (byte_t *p = start_ptr; p - start_ptr < len; p += d_len) {
          if (p > start_ptr) {
            ss << ",";
          }
          d_len = *p;
          p += 1;          
          debug(0, "d_len = %d, p - s (%d)", d_len, p - start_ptr);

          if (p - start_ptr + d_len > len) {
            break;
          }
          ss << std::string(reinterpret_cast<char *>(p), d_len);
        }
        s = ss.str();
      }
      break;

    case 32: // NB
      {
        
      }
      break;

    default:
      {
        std::stringstream ss;
        size_t len;
        byte_t *p, *start_ptr = this->ptr(&len);
        debug (0, "unsupported name service type: %d", this->type_);
        for(p = start_ptr; p - start_ptr < len; p++) {
          char c = static_cast<char>(*p);
          ss << (isprint(c) ? c : '.');
        }
        s = ss.str();
      }
    }
    return s;
  }

  void NameServiceDecoder::VarNameServiceData::set_data (byte_t * ptr,
                                                         size_t len,
                                                         u_int16_t type,
                                                         byte_t * base_ptr,
                                                         size_t total_len) {
    this->set (ptr, len);
    this->type_ = type;
    this->base_ptr_ = base_ptr;
    this->total_len_ = total_len;
  }

  std::string NameServiceDecoder::VarNameServiceName::repr() const {
    size_t len;
    byte_t * ptr = this->ptr(&len);
    byte_t * rp;
    std::string s;
    rp = NameServiceDecoder::parse_label (ptr, len, this->base_ptr_,
                                          this->total_len_, &s);
    return (rp != NULL) ? s : Value::null_;
  }

  void NameServiceDecoder::VarNameServiceName::set_data
  (byte_t * ptr, size_t len, byte_t * base_ptr, size_t total_len) {
    this->set (ptr, len);
    this->base_ptr_ = base_ptr;
    this->total_len_ = total_len;
  }

  NameServiceDecoder::NameServiceDecoder (NetDec * nd,
                                          const std::string &base_name) :
    Decoder (nd), base_name_ (base_name) {
    const std::string &bn = this->base_name_;

    // Assign event name
    this->EV_NS_PKT_ = nd->assign_event (bn + ".packet", bn + " Packet");

    // Assign parameter name
    this->P_ID_  = nd->assign_value(bn + ".tx_id", bn + " Transaction ID",
                                    new FacNum ());
    this->P_QUERY_ = nd->assign_value(bn + ".query", bn + " Query Flag");

    for (size_t i = 0; i < RR_CNT; i++) {
      std::string base, desc;
      switch (i) {
      case RR_QD: base = "qd"; desc = bn + " Question"; break;
      case RR_AN: base = "an"; desc = bn + " Answer RP"; break;
      case RR_NS: base = "ns"; desc = bn + " Authority RP"; break;
      case RR_AR: base = "ar"; desc = bn + " Additional RP"; break;
      default: assert (0);
      }

      std::string ev_name = bn + "." + base;
      this->EV_TYPE_[i] = nd->assign_event (ev_name, desc);

      std::string name_key = bn + "." + base + "_name";
      std::string type_key = bn + "." + base + "_type";
      std::string data_key = bn + "." + base + "_data";
      this->NS_NAME[i] = nd->assign_value(name_key, desc + " Name",
                                          new FacNameServiceName ());
      this->NS_TYPE[i] = nd->assign_value(type_key, desc + " Type",
                                          new FacType ());
      this->NS_DATA[i] = nd->assign_value(data_key, desc + " Data",
                                          new FacNameServiceData ());
    }
  }

  void NameServiceDecoder::setup (NetDec * nd) {
    // No upper decoder is needed
  };

  bool NameServiceDecoder::ns_decode (Property *p) {
    const size_t hdr_len = sizeof (struct ns_header);
    byte_t *base_ptr = p->payload (hdr_len);

    if (base_ptr == NULL) {
      return false;
    }

    struct ns_header * hdr =
      reinterpret_cast<struct ns_header*> (base_ptr);

    p->push_event (this->EV_NS_PKT_);

    int rr_count[4], rr_delim[4];
    rr_count[RR_QD] = ntohs (hdr->qd_count_);
    rr_count[RR_AN] = ntohs (hdr->an_count_);
    rr_count[RR_NS] = ntohs (hdr->ns_count_);
    rr_count[RR_AR] = ntohs (hdr->ar_count_);
    int rr_total =
      rr_count[RR_QD] + rr_count[RR_AN] + rr_count[RR_NS] + rr_count[RR_AR];

    for (int i = 0; i < 4; i++) {
      if (rr_count[i] > 0) {
        p->push_event (this->EV_TYPE_[i]);
      }
    }

    for (int i = 0; i < 4; i++) {
      rr_delim[i] = (i == 0 ? 0 : (rr_delim[i - 1] + rr_count[i - 1]));
    }

    debug (DEBUG, "trans_id:0x%04X, flags:%04X, qd=%d, an=%d, ns=%d, ar=%d",
           hdr->trans_id_, hdr->flags_, rr_count[RR_QD], rr_count[RR_AN],
           rr_count[RR_NS], rr_count[RR_AR]);

    const size_t total_len = p->remain ();
    byte_t *ptr = p->payload (total_len);
    assert (ptr != NULL);
    const byte_t * ep = base_ptr + hdr_len + total_len;

    p->set (this->P_ID_, &(hdr->trans_id_), sizeof (hdr->trans_id_));
    u_int32_t query = htonl(((hdr->flags_ & NS_FLAG_MASK_QUERY) > 0) ? 1 : 0);
    p->copy (this->P_QUERY_, &(query), sizeof(query));

    // parsing resource record
    int target = 0, rr_c = 0;
    for (int c = 0; c < rr_total; c++) {
      while (rr_c >= rr_count[target]) {
        rr_c = 0;
        target++;
        assert (target < RR_CNT);
      }
      rr_c++;

      int remain = ep - ptr;
      // assert (ep - ptr > 0);
      if (ep <= ptr) {
        return false;
      }

      VarNameServiceName * vn =
        dynamic_cast <VarNameServiceName*> (p->retain (this->NS_NAME[target]));
      assert (vn != NULL);
      vn->set_data (ptr, remain, base_ptr, total_len);

      if (NULL == (ptr = NameServiceDecoder::parse_label (ptr, remain, base_ptr,
                                                          total_len, NULL))) {
        debug (DEBUG, "label parse error");
        break;
      }

      // assert (ep - ptr);
      if (ep <= ptr) {
        return false;
      }

      if (ep - ptr < static_cast<int>(sizeof (struct ns_rr_header))) {
        debug (DEBUG, "not enough length: %ld", ep - ptr);
        break;
      }
      struct ns_rr_header * rr_hdr =
        reinterpret_cast <struct ns_rr_header*>(ptr);
      ptr += sizeof (struct ns_rr_header);

      // set value
      p->set (this->NS_TYPE[target], &(rr_hdr->type_),
              sizeof (rr_hdr->type_));

      // has resource data field
      if (c >= rr_count[RR_QD]) {
        if (ep - ptr < static_cast<int>(sizeof (struct ns_ans_header))) {
          debug (DEBUG, "not enough length: %ld", ep - ptr);
          break;
        }
        struct ns_ans_header * ans_hdr =
          reinterpret_cast<struct ns_ans_header*> (ptr);
        ptr += sizeof (struct ns_ans_header);
        const size_t rd_len = ntohs (ans_hdr->rd_len_);

        if (ep - ptr < static_cast<int>(rd_len)) {
          debug (DEBUG, "not match resource record len(%zd) and remain (%zd)",
                 rd_len, ep - ptr);
          break;
        }

        // set value
        VarNameServiceData * v = dynamic_cast <VarNameServiceData*>
          (p->retain (this->NS_DATA[target]));
        assert (v != NULL);
        v->set_data (ptr, rd_len, htons (rr_hdr->type_), base_ptr, total_len);

        // seek pointer
        ptr += rd_len;
      }
    }

    if (ep != ptr) {
      debug (DEBUG, "fail to parse (remain:%ld)", ep - ptr);
    }

    return true;
  }

  // Main decoding function.
  bool NameServiceDecoder::decode (Property *p) {
    return this->ns_decode (p);
  };


  byte_t * NameServiceDecoder::parse_label (byte_t * p, size_t remain,
                                    const byte_t * sp,
                                    const size_t total_len,
                                            std::string * s) {
    const size_t min_len = 1;
    const size_t dst_len = 2;
    const size_t max_len = 256;
    size_t len = 0;

    bool DEBUG = false;
    if (s) {
      s->erase ();
    }

    byte_t * rp = NULL;

    while (len < max_len) {
      if (remain < min_len) {
        debug (DEBUG, "not enough length: %zd", remain);
        return NULL;
      }

      // jump if needed
      if ((*p & 0xC0) == 0xC0) {
        if (remain < dst_len) {
          debug (DEBUG, "not enough jump destination length: %zd", remain);
          return NULL;
        }

        u_int16_t * h = reinterpret_cast <u_int16_t *>(p);
        u_int16_t jmp = (ntohs (*h) & 0x3FFF);

        if (jmp >= total_len) {
          debug (DEBUG, "invalid jump point: %d", jmp);
          return NULL;
        }
        if (rp == NULL) {
          rp = p + dst_len;
        }
        p = const_cast<byte_t*> (&(sp[jmp]));
        remain = total_len - (jmp);
      }

      // retain payload
      int data_len = *p;
      if (data_len == 0) {
        return (rp == NULL ? p + 1 : rp);
      }
      if (data_len + min_len >= remain) {
        debug (DEBUG, "invalid data length: %d (remain:%zd)",
               data_len, remain);
        return NULL;
      }

      if (s) {
        s->append (reinterpret_cast<char*>(p + 1), data_len);
        s->append (".", 1);
      }
      len += data_len;

      p += data_len + 1;
      remain -= data_len + 1;
    }

    // if exiting loop, 
    debug (DEBUG, "too long domain name (invalid)");
    return NULL;
  }

  std::string NameServiceDecoder::VarType::repr() const {
    u_int16_t type = this->ntoh <u_int16_t>();
    std::string s;
    switch (type) {
    case  1: s.assign ("A"); break;
    case  2: s.assign ("NS"); break;
    case  5: s.assign ("CNAME"); break;
    case  6: s.assign ("SOA"); break;
    case 12: s.assign ("PTR"); break;
    case 15: s.assign ("MX"); break;
    case 16: s.assign ("TXT"); break;
    case 28: s.assign ("AAAA"); break;
    default:
      {
        std::stringstream ss;
        ss << type;
        s = ss.str();
      }
      break;
    }

    debug(0, "type = %u, %s", type, s.c_str());
    return s;
  }

}  // namespace swarm
