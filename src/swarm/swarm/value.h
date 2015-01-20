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


#ifndef SRC_VALUE_H__
#define SRC_VALUE_H__

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <string.h>

#include "./common.h"

namespace swarm {
  // -------------------------------------------------------
  // Value
  //
  class Value {
  private:
    byte_t *ptr_;
    byte_t *buf_;
    size_t len_;
    size_t buf_len_;

  public:
    static const std::string null_;

    Value ();
    ~Value ();
    void init ();
    void set (byte_t *ptr, size_t len);
    void copy (byte_t *ptr, size_t len);
    byte_t *ptr (size_t *len=nullptr) const;
    
    virtual std::string repr() const;
    std::string str() const;
    std::string hex() const;
    std::string ip4() const;
    std::string ip6() const;
    std::string mac() const;
    std::string prt() const;

    template <typename T> T ntoh () const {
      if (this->len_ >= sizeof (T)) {
        T * p = reinterpret_cast <T *> (this->ptr_);

        if (sizeof (T) == 2) {
          return ntohs (*p);
        } else if (sizeof (T) == 4) {
          return ntohl (*p);
        } else {
          // ToDo: properly handle 64bit number
          return *p;
        }
      } else {
        // when not enough lenght, adjust to unsigned integer
        T n = 0;

        if (this->len_ == 1) {
          u_int8_t *p = reinterpret_cast<u_int8_t* > (this->ptr_);
          n = static_cast<T> (*p);
        } else if (2 == this->len_ || 3 == this->len_) {
          u_int16_t *p = reinterpret_cast<u_int16_t* > (this->ptr_);
          n = static_cast<T> (ntohs (*p));
        } else if (4 <= this->len_ && this->len_ <= 7) {
          u_int32_t *p = reinterpret_cast<u_int32_t* > (this->ptr_);
          n = static_cast<T> (ntohl (*p));
        }

        return n;
      }
    }

    uint32_t uint32() const;
    uint64_t uint64() const;

    virtual bool is_null() const { return (this->ptr_ == nullptr); }
    bool operator==(const Value &v) const {
      return (this->len_ == v.len_ && 
              0 == ::memcmp(this->ptr_, v.ptr_, this->len_));
    }
  };

  // -------------------------------------------------------
  // ValueNull
  //
  class ValueNull : public Value {
  private:
    static const std::string v_;

  public:
    ValueNull() {}
    ~ValueNull() {}
    std::string repr() const { return this->v_; }
    bool is_null() const { return true; }
    byte_t *ptr (size_t *len=nullptr) const { return nullptr; }    
  };

  // -------------------------------------------------------
  // ValueSet
  //
  class ValueSet {
  private:
    std::vector <Value*> value_set_;
    size_t idx_;
    ValueFactory * fac_;

  public:
    static const std::string errmsg_;

    explicit ValueSet(ValueFactory *fac = nullptr);
    ~ValueSet();
    void init ();

    void push (byte_t *data, size_t len, bool copy = false);
    Value *retain ();    
    size_t size () const;
    Value *get(size_t idx) const;
  };

  // -------------------------------------------------------
  // ValueEntry
  //
  class ValueEntry {
  private:
    val_id vid_;
    std::string name_;
    std::string desc_;
    ValueFactory * fac_;

  public:
    ValueEntry (val_id vid, const std::string &name,
                const std::string &desc_, ValueFactory * fac);
    ~ValueEntry ();
    val_id vid () const;
    const std::string& name () const;
    const std::string& desc () const;
    ValueFactory * fac () const;
  };

  // -------------------------------------------------------
  // ValueFactory
  //
  class ValueFactory {
  public:
    ValueFactory() {}
    virtual ~ValueFactory() {}
    virtual Value * New() { return new Value (); }
  };

#define DEF_REPR_CLASS(V_NAME, F_NAME)              \
  class V_NAME : public Value {                     \
  public: std::string repr () const;                \
  };                                                \
  class F_NAME : public ValueFactory {              \
  public: Value * New () { return new V_NAME (); }  \
  };


  // extended classes
  DEF_REPR_CLASS (ValueIPv4, FacIPv4);
  DEF_REPR_CLASS (ValueIPv6, FacIPv6);
  DEF_REPR_CLASS (ValueMAC,  FacMAC);
  DEF_REPR_CLASS (ValueNum,  FacNum);


}  // namespace swarm

#endif  // SRC_VALUE_H__
