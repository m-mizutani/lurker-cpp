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


#include <arpa/inet.h>
#include <string.h>
#include <assert.h>

#include "./swarm/property.h"
#include "./swarm/value.h"
#include "./swarm/netdec.h"
#include "./debug.h"

namespace swarm {
  // -------------------------------------------------------
  // Param
  const std::string ValueSet::errmsg_ = "(error)";
  const ValueNull Property::val_null_;



  // -------------------------------------------------------
  // Property
  Property::Property (NetDec * nd) : 
    nd_(nd), 
    buf_(nullptr),
    val_hist_(VAL_HIST_MAX), 
    val_hist_ptr_(0) {
    this->nd_->build_value_vector (&(this->value_));
  }
  Property::~Property () {
    /*
    if (this->buf_) {
      free (this->buf_);
    }
    */
  }
  void Property::init  (const byte_t *data, const size_t cap_len,
                        const size_t data_len, const struct timeval &tv) {
    // In this version, init is now zero-copy implementation
    /*
    if (this->buf_len_ < cap_len) {
      this->buf_len_ = cap_len;
      this->buf_ = static_cast <byte_t *>
        (::realloc (static_cast <void*> (this->buf_), this->buf_len_));
    }
    */

    this->tv_sec_   = tv.tv_sec;
    this->tv_usec_  = tv.tv_usec;
    this->data_len_ = data_len;
    this->cap_len_  = cap_len;
    this->ptr_      = 0;

    // In this version, init is now zero-copy implementation
    // assert (this->buf_len_ >= cap_len);
    // ::memcpy (this->buf_, data, cap_len);
    this->buf_ = data;

    for (size_t i = 0; i < this->val_hist_ptr_; i++) {
      this->value_[this->val_hist_[i]]->init ();
    }

    this->val_hist_ptr_ = 0;
    this->ev_push_ptr_ = 0;
    this->ev_pop_ptr_ = 0;

    this->addr_len_ = 0;
    this->port_len_ = 0;
    this->proto_ = 0;
    this->hash_value_ = 0;
    this->hashed_ = false;
    this->dir_ = DIR_NIL;

    this->src_port_ = nullptr;
    this->dst_port_ = nullptr;
    this->src_addr_ = nullptr;
    this->dst_addr_ = nullptr;
  }
  const Value& Property::value(const std::string &key, size_t idx) const {
    const val_id vid = this->nd_->lookup_value_id (key);
    return this->value(vid, idx);
  }
  const Value& Property::value(const val_id vid, size_t idx) const {
    if (vid == VALUE_NULL) {
      return Property::val_null_;
    }

    size_t p = Property::vid2idx (vid);
    assert(this->value_[p] != nullptr);
    Value *v = this->value_[p]->get(idx);
    if (v) {
      return *v;
    } else {
      return Property::val_null_;
    }
  }
  size_t Property::value_size(const std::string &key) const {
    const val_id vid = this->nd_->lookup_value_id (key);
    return this->value_size(vid);
  }
  size_t Property::value_size(const val_id vid) const {
    if (vid == VALUE_NULL) {
      return 0;
    }

    size_t p = Property::vid2idx (vid);
    return this->value_[p]->size();
  }


  size_t Property::len () const {
    return this->data_len_;
  }
  size_t Property::cap_len () const {
    return this->cap_len_;
  }
  void Property::tv (struct timeval *tv) const {
    tv->tv_sec = this->tv_sec_;
    tv->tv_usec = this->tv_usec_;
  }
  time_t Property::tv_sec() const {
    return this->tv_sec_;
  }
  time_t Property::tv_usec() const {
    return this->tv_usec_;
  }
  double Property::ts () const {
    double ts = static_cast <double> (this->tv_sec_) +
      static_cast <double> (this->tv_usec_) / 1000000;
    return ts;
  }
  byte_t * Property::refer (size_t alloc_size) {
    // Swarm supports maximum 16MB for one packet lengtsh
    assert (alloc_size < 0xfffffff);
    assert (this->ptr_ < 0xfffffff);

    if (this->ptr_ + alloc_size <= this->cap_len_) {
      size_t p = this->ptr_;
      return const_cast<byte_t*>(&(this->buf_[p]));
    } else {
      return nullptr;
    }
  }

  byte_t * Property::payload (size_t alloc_size) {
    // Swarm supports maximum 16MB for one packet lengtsh
    byte_t * p = this->refer (alloc_size);
    if (p) {
      this->ptr_ += alloc_size;
    }
    return p;
  }
  size_t Property::remain () const {
    if (this->ptr_ < this->cap_len_) {
      return (this->cap_len_ - this->ptr_);
    } else {
      return 0;
    }
  }

  void Property::addr2str (void * addr, size_t len, std::string *s) {
    char buf[32];
    if (len == 4) {
      ::inet_ntop (AF_INET, addr, buf, sizeof (buf));
      s->assign (buf);
    } else if (len == 16) {
      ::inet_ntop (AF_INET6, addr, buf, sizeof (buf));
      s->assign (buf);
    } else {
      s->assign ("unsupported address");
    }
  }
  std::string Property::src_addr () const {
    std::string buf;
    addr2str (this->src_addr_, this->addr_len_, &buf);
    return buf;
  }
  std::string Property::dst_addr () const {
    std::string buf;
    addr2str (this->dst_addr_, this->addr_len_, &buf);
    return buf;
  }
  void *Property::src_addr (size_t *len) const {
    if (len) {
      *len = this->addr_len_;
    }
    return this->src_addr_;
  }
  void *Property::dst_addr (size_t *len) const {
    if (len) {
      *len = this->addr_len_;
    }
    return this->dst_addr_;
  }

  int Property::src_port () const {
    if (this->port_len_ == 2) {
      u_int16_t * p = static_cast<u_int16_t*> (this->src_port_);
      return static_cast<int> (ntohs (*p));
    } else {
      // unsupported
      return 0;
    }
  }
  int Property::dst_port () const {
    if (this->port_len_ == 2) {
      u_int16_t * p = static_cast<u_int16_t*> (this->dst_port_);
      return static_cast<int> (ntohs (*p));
    } else {
      // unsupported
      return 0;
    }
  }
  bool Property::has_port() const {
    return (this->src_port_ || this->dst_port_);
  }
  std::string Property::proto () const {
    static const u_int8_t PROTO_ICMP  = 1;
    static const u_int8_t PROTO_TCP   = 6;
    static const u_int8_t PROTO_UDP   = 17;
    static const u_int8_t PROTO_IPV6  = 41;
    static const u_int8_t PROTO_ICMP6 = 58;

    std::string s;
    switch (this->proto_) {
    case PROTO_ICMP:  s = "ICMP";    break;
    case PROTO_TCP:   s = "TCP";     break;
    case PROTO_UDP:   s = "UDP";     break;
    case PROTO_IPV6:  s = "IPv6";    break;
    case PROTO_ICMP6: s = "ICMPv6";  break;
    default:          s = "unknown"; break;
    }

    return s;
  }

  uint64_t Property::hash_value () const {
    return this->hash_value_ ;
  }
  FlowDir Property::dir() const {
    if (this->hashed_) {
      return this->dir_;
    } else {
      return DIR_NIL;
    }
  }
  const void *Property::ssn_label(size_t *len) const {
    assert(len != nullptr);
    *len = this->addr_len_ * sizeof(uint32_t);
    return static_cast<const void *>(this->ssn_label_);
  }

  Value * Property::retain (const std::string &value_name) {
    const val_id vid = this->nd_->lookup_value_id (value_name);
    if (vid == VALUE_NULL) {
      return nullptr;
    } else {
      return this->retain (vid);
    }
  }
  Value * Property::retain (const val_id vid) {
    size_t idx = static_cast <size_t> (vid - VALUE_BASE);
    this->set_val_history(idx);
    if (idx < this->value_.size ()) {
      Value * v = this->value_[idx]->retain ();
      return v;
    } else {
      return nullptr;
    }
  }

  void Property::set_val_history(size_t v_idx) {
    if (this->val_hist_ptr_ < VAL_HIST_MAX) {
      this->val_hist_[this->val_hist_ptr_] = v_idx;
      this->val_hist_ptr_++;
    }
  }

  bool Property::set (const std::string &value_name, void * ptr, size_t len) {
    const val_id vid = this->nd_->lookup_value_id (value_name);
    if (vid == VALUE_NULL) {
      return false;
    } else {
      return this->set (vid, ptr, len);
    }
  }
  bool Property::set (const val_id vid, void * ptr, size_t len) {
    Value *v = this->retain(vid);
    if (v) {
      v->set(reinterpret_cast<byte_t*>(ptr), len);
      return true;
    } else {
      return false;
    }
  }

  /*
    if (idx < this->value_.size () && ptr) {
      assert (idx < this->value_.size () && this->value_[idx] != NULL);
      this->value_[idx]->push (static_cast <byte_t*> (ptr), len);
      return true;
    } else {
      return false;
    }
    } */
  bool Property::copy (const std::string &value_name, void * ptr, size_t len) {
    const val_id vid = this->nd_->lookup_value_id (value_name);
    if (vid == VALUE_NULL) {
      return false;
    } else {
      return this->copy (vid, ptr, len);
    }
  }
  bool Property::copy (const val_id vid, void * ptr, size_t len) {
    Value *v = this->retain(vid);
    if (v) {
      v->copy(reinterpret_cast<byte_t*>(ptr), len);
      return true;
    } else {
      return false;
    }
    /*    
    size_t idx = static_cast <size_t> (vid - VALUE_BASE);
    
    if (idx < this->value_.size () && ptr) {
      assert (idx < this->value_.size () && this->value_[idx] != NULL);
      this->value_[idx]->push (static_cast <byte_t*> (ptr), len, true);
      this->set_val_history(idx);
      return true;
    } else {
      return false;
      }*/
  }

  FlowDir Property::get_dir(void *src_addr, void *dst_addr, size_t addr_len,
                            void *src_port, void *dst_port, size_t port_len) {
    // Determine flow direction by IP addresses and port numbers
    // Low address or low port number means LEFT, high one means RIGHT
    FlowDir dir = DIR_NIL;

    int rc_addr = ::memcmp (src_addr, dst_addr, addr_len);
    if (rc_addr < 0) { // src is Left, dst is Right
      dir = DIR_L2R;
    } else if (rc_addr > 0) {
      dir = DIR_R2L;
    }

    if (dir == DIR_NIL) {
      int rc_port = ::memcmp (src_port, dst_port, port_len);
      if (rc_port < 0) { // src is Left, dst is Right
        dir = DIR_L2R;
      } else if (rc_port > 0) {
        dir = DIR_R2L;
      } 
    }

    // If dir is DIR_NIL, it means that LEFT and RIGHT could not be determined
    return dir;
  }

  void Property::calc_hash () {
    if (this->hashed_) {
      // don't allow override
      return;
    }

    uint32_t *la, *ra;
    uint16_t *lp, *rp;
    uint32_t *p = this->ssn_label_;
    this->dir_ =
      Property::get_dir(this->src_addr_, this->dst_addr_, this->addr_len_,
                        this->src_port_, this->dst_port_, this->port_len_);

    // Set IP addresses and TCP/UDP port.
    if (this->dir_ == DIR_L2R) {
      la = static_cast <uint32_t *>(this->src_addr_);
      ra = static_cast <uint32_t *>(this->dst_addr_);
      lp = static_cast <uint16_t *>(this->src_port_);
      rp = static_cast <uint16_t *>(this->dst_port_);
    } else {
      assert(this->dir_ == DIR_R2L || this->dir_ == DIR_NIL);
      ra = static_cast <uint32_t *>(this->src_addr_);
      la = static_cast <uint32_t *>(this->dst_addr_);
      rp = static_cast <uint16_t *>(this->src_port_);
      lp = static_cast <uint16_t *>(this->dst_port_);
    }
    
    // Copy IP address, port number into buffer.
    memcpy(p, la, this->addr_len_);
    p += this->addr_len_ / 4;
    memcpy(p, ra, this->addr_len_);
    p += this->addr_len_ / 4;

    if (this->port_len_ == 2) {
      uint32_t t = static_cast<uint32_t>(*lp);
      *p =  (t << 16) + static_cast<uint32_t>(*rp);
    } else {
      *p = 0;
    }
    p++;

    // Set IP_PROTOCOL as unsigned 32bit integer
    *p = static_cast<uint32_t>(this->proto_);
    p++;

    // Set `session label length`
    this->ssn_label_len_ = p - this->ssn_label_;
    assert(this->ssn_label_len_ < SSN_LABEL_MAX);

    // Calculate hash value.
    u_int64_t h = 1125899906842597;
    for (size_t i = 0; i < this->ssn_label_len_; i++) {
      h = (this->ssn_label_[i] + (h << 6) + (h << 16) - h);
    }

    this->hashed_ = true;
    this->hash_value_ = h;
  }
  void Property::set_addr (void *src_addr, void *dst_addr, u_int8_t proto,
                           size_t addr_len) {
    this->addr_len_ = addr_len;
    this->src_addr_ = src_addr;
    this->dst_addr_ = dst_addr;
    this->proto_ = proto;
  }
  void Property::set_port (void *src_port, void *dst_port, size_t port_len) {
    this->port_len_ = port_len;
    this->src_port_ = src_port;
    this->dst_port_ = dst_port;
  }

  ev_id Property::pop_event () {
    assert (this->ev_pop_ptr_ <= this->ev_push_ptr_);
    if (this->ev_pop_ptr_ < this->ev_push_ptr_) {
      const size_t i = this->ev_pop_ptr_++;
      return this->ev_queue_[i];
    } else {
      return EV_NULL;
    }
  }
  void Property::push_event (const ev_id eid) {
    if (this->ev_push_ptr_ >= this->ev_queue_.size ()) {
      // prevent frequet call of memory allocation
      this->ev_queue_.resize (this->ev_queue_.size () +
                              Property::EV_QUEUE_WIDTH);
    }
    this->ev_queue_[this->ev_push_ptr_] = eid;
    this->ev_push_ptr_++;
  }

}  // namespace swarm
