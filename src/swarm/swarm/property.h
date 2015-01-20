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

#ifndef SRC_PROPERTY_H__
#define SRC_PROPERTY_H__

#include <assert.h>
#include <sys/types.h>
#include <string>
#include <map>
#include <vector>
#include <deque>

#include "./common.h"
#include "./value.h"

namespace swarm {
  class NetDec;


  // -------------------------------------------------------
  // Property
  //
  class Property {
  public:

  private:
    NetDec * nd_;
    time_t tv_sec_;
    time_t tv_usec_;

    // buffer for payload management
    const byte_t *buf_;
    // size_t buf_len_;
    size_t data_len_;
    size_t cap_len_;
    size_t ptr_;

    // Parameter management
    std::vector <ValueSet *> value_;
    std::vector <size_t> val_hist_;
    size_t val_hist_ptr_;
    static const size_t VAL_HIST_MAX = 1024;

    // Event management
    std::vector <ev_id> ev_queue_;
    size_t ev_pop_ptr_;
    size_t ev_push_ptr_;
    static const size_t EV_QUEUE_WIDTH = 128;


    u_int8_t proto_;
    size_t addr_len_;
    void *src_addr_, *dst_addr_;
    size_t port_len_;
    void *src_port_, *dst_port_;

    bool hashed_;
    uint64_t hash_value_;
    FlowDir dir_;

    static const size_t SSN_LABEL_MAX = 128;
    uint32_t ssn_label_[SSN_LABEL_MAX];
    size_t ssn_label_len_;

    static const ValueNull val_null_;

    static inline FlowDir get_dir(void *src_addr, void *dst_addr, size_t addr_len,
                                  void *src_port, void *dst_port, size_t port_len);
    void set_val_history(size_t v_idx);

  public:
    explicit Property (NetDec * nd);
    ~Property ();
    void init (const byte_t *data, const size_t cap_len,
               const size_t data_len, const struct timeval &tv);
    Value * retain (const std::string &value_name);
    Value * retain (const val_id vid);
    bool set (const std::string &value_name, void * ptr, size_t len);
    bool set (const val_id vid, void * ptr, size_t len);
    bool copy (const std::string &value_name, void * ptr, size_t len);
    bool copy (const val_id vid, void * ptr, size_t len);

    void set_addr (void *src_addr, void *dst_addr, u_int8_t proto,
                   size_t addr_len);
    void set_port (void *src_port, void *dst_port, size_t port_len);
    void calc_hash ();

    ev_id pop_event ();
    void push_event (const ev_id eid);

    const Value &value(const std::string &key, size_t idx=0) const;
    const Value &value(const val_id vid, size_t idx=0) const;
    size_t value_size(const std::string &key) const;
    size_t value_size(const val_id vid) const;
    
    size_t len () const;      // original data length
    size_t cap_len () const;  // captured data length
    void tv (struct timeval *tv) const;
    time_t tv_sec() const;
    time_t tv_usec() const;
    double ts () const;

    // ToDo(masa): byte_t * refer() should be const byte_t * refer()
    byte_t * refer (size_t alloc_size);
    // ToDo(masa): byte_t * payload() should be const byte_t * payload()
    byte_t * payload (size_t alloc_size);
    size_t remain () const;

    std::string src_addr () const;
    std::string dst_addr () const;
    void *src_addr (size_t *len) const;
    void *dst_addr (size_t *len) const;
    int src_port () const;
    int dst_port () const;
    bool has_port () const;
    std::string proto () const;
    uint64_t hash_value () const;
    const void *ssn_label(size_t *len) const;
    FlowDir dir() const;
    inline static size_t vid2idx (val_id vid) {
      return static_cast <size_t> (vid - VALUE_BASE);
    }
    inline static void addr2str (void * addr, size_t len, std::string *s);
  };
}  // namespace swarm

#endif  // SRC_PROPERTY_H__
