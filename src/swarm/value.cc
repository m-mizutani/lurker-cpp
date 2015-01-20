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
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>

#include "./swarm/value.h"
#include "./debug.h"

namespace swarm {
  const std::string Value::null_("(none)");
  const std::string ValueNull::v_("(null)");

  ValueSet::ValueSet(ValueFactory * fac) : idx_(0), fac_(fac) {
  }
  ValueSet::~ValueSet() {
  }
  void ValueSet::init () {
    this->idx_ = 0;
  }
  size_t ValueSet::size () const {
    return this->idx_;
  }
  Value * ValueSet::retain () {
    Value * v;
    if (this->idx_ >= this->value_set_.size ())  {
      v = (this->fac_) ? this->fac_->New () : new Value ();
      this->value_set_.push_back (v);
      this->idx_++;
      assert (this->idx_ == this->value_set_.size ());
    } else {
      v = this->value_set_[this->idx_];
      this->idx_++;
    }

    v->init();
    return v;
  }
  Value * ValueSet::get (size_t idx) const {
    assert(0 <= idx);
    if (idx < this->idx_) {
      return this->value_set_[idx];
    } else {
      return nullptr;
    }
  }


  // -------------------------------------------------------
  // Value
  Value::Value () : ptr_(nullptr), buf_(nullptr),  len_(0), buf_len_(0) {
  }
  Value::~Value () {
    if (this->buf_) {
      free (this->buf_);
    }
  }
  void Value::init () {
    this->ptr_ = nullptr;
    this->len_ = 0;
  }
  void Value::set (byte_t *ptr, size_t len) {
    this->ptr_ = ptr;
    this->len_ = len;
  }
  void Value::copy (byte_t *ptr, size_t len) {
    if (this->buf_len_ < len) {
      this->buf_len_ = len;
      this->buf_ = static_cast <byte_t*> (realloc (this->buf_, this->buf_len_));
    }

    ::memcpy (this->buf_, ptr, len);
    this->ptr_ = this->buf_;
    this->len_ = len;
  }

  byte_t *Value::ptr (size_t *len) const {
    if (len) {
      *len = this->len_;
    } 
    return this->ptr_;
  }

  std::string Value::repr() const {
    return this->str();
  }
  std::string Value::str() const {
    if (this->ptr_) {
      std::string v(reinterpret_cast<char *> (this->ptr_), this->len_);
      return v;
    } else {
      return this->Value::null_;
    }
  }
  std::string Value::hex() const {
    byte_t * p = this->ptr_;
    std::stringstream ss;

    if (p) {
      char t[4];
      for (size_t i = 0; i < this->len_; i++) {
        snprintf (t, sizeof (t), "%02X", p[i]);
        ss << t;
        if (i < this->len_ - 1) {
          ss << " ";
        }
      }

      return ss.str();
    } else {
      return Value::null_;
    }
  }

  std::string Value::ip4() const {
    byte_t * p = this->ptr_;

    if (p && this->len_ >= 4) {
      char t[32];
      ::inet_ntop (PF_INET, static_cast<void*>(p), t, sizeof (t));
      std::string v(t);
      return v;
    } else {
      return Value::null_;
    }
  }

  std::string Value::ip6() const {
    byte_t * p = this->ptr_;

    if (p && this->len_ >= 16) {
      char t[128];
      ::inet_ntop (PF_INET6, static_cast<void*>(p), t, sizeof (t));
      std::string v(t);
      return v;
    } else {
      return Value::null_;
    }
  }
  std::string Value::mac() const {
    byte_t * p = this->ptr_;

    if (p && this->len_ == 6) {
      std::stringstream ss;
      for (size_t i = 0; i < this->len_; i++) {
        char t[4];
        snprintf (t, sizeof (t), "%02X", p[i]);
        ss << t;
        if (i < this->len_ - 1) {
          ss << ":";
        }
      }
      return ss.str();
    } else {
      return Value::null_;
    }
  }
  std::string Value::prt() const {
    char *buf = new char[this->len_];
    for(size_t i = 0; i < this->len_; i++) {
      buf[i] = (isprint(this->ptr_[i]) > 0) ? this->ptr_[i] : '.';
    }
    std::string tmp(buf, this->len_);
    return tmp;
  }

  uint32_t Value::uint32() const {
    return this->ntoh <uint32_t> ();
  }
  uint64_t Value::uint64() const {
    return this->ntoh <uint64_t> ();
  }


  // -------------------------------------------------------
  // ValueEntry
  ValueEntry::ValueEntry (val_id vid, const std::string &name,
                          const std::string &desc, ValueFactory * fac) :
    vid_(vid), name_(name), desc_(desc), fac_(fac) {
    // ValueEntry has responsibility to manage fac (ValueFactory)
  }
  ValueEntry::~ValueEntry () {
    delete this->fac_;
  }
  val_id ValueEntry::vid () const {
    return this->vid_;
  }
  const std::string& ValueEntry::name () const {
    return this->name_;
  }
  const std::string& ValueEntry::desc () const {
    return this->desc_;
  }
  ValueFactory * ValueEntry::fac () const {
    return this->fac_;
  }



  std::string ValueIPv4::repr() const {
    return this->ip4();
  }
  std::string ValueIPv6::repr() const {
    return this->ip6();
  }
  std::string ValueMAC::repr() const {
    return this->mac();
  }
  std::string ValueNum::repr () const {
    std::stringstream ss;
    ss << this->uint64();
    return ss.str();
  }

}  // namespace swarm
