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

#ifndef SRC_NETDEC_H__
#define SRC_NETDEC_H__

#include <map>
#include <vector>
#include <deque>
#include <string>
#include "./common.h"
#include "../swarm.h"

namespace swarm {
  // ----------------------------------------------------------
  // Handler
  class Handler {
  public:
    Handler ();
    virtual ~Handler ();
    virtual void recv (ev_id eid, const Property &p) = 0;
  };


  class HandlerEntry {
  private:
    hdlr_id id_;
    ev_id ev_;
    Handler * hdlr_;

  public:
    HandlerEntry (hdlr_id hid, ev_id eid, Handler * hdlr_);
    ~HandlerEntry ();
    Handler * hdlr () const;
    hdlr_id id () const;
    ev_id ev () const;
  };

  class NetDec {
  private:
    std::map <std::string, ev_id> fwd_event_;
    std::map <ev_id, std::string> rev_event_;
    std::map <std::string, ValueEntry *> fwd_value_;
    std::map <val_id, ValueEntry *> rev_value_;
    std::map <std::string, dec_id> fwd_dec_;
    std::map <dec_id, std::string> rev_dec_;
    std::map <hdlr_id, HandlerEntry *> rev_hdlr_;
    dec_id base_did_;
    ev_id base_eid_;
    val_id base_vid_;
    hdlr_id base_hid_;
    dec_id new_dec_id ();
      

    const std::string none_;
    std::vector <Decoder *> dec_mod_;
    std::vector <std::map<dec_id, dec_id> > dec_bind_;
    dec_id install_dec_mod (const std::string &name, Decoder *dec);
    Decoder* uninstall_dec_mod (dec_id d_id);

    std::vector <std::deque <HandlerEntry *> * > event_handler_;
    dec_id dec_default_;
    Property * prop_;

    // now can count by 16 Exa byte/packet
    uint64_t recv_len_;
    uint64_t cap_len_;
    uint64_t recv_pkt_;
    struct timespec init_ts_;
    struct timespec last_ts_;

    inline static size_t eid2idx (const ev_id eid) {
      return static_cast <size_t> (eid - EV_BASE);
    }

    std::string errmsg_;

  public:
    NetDec ();
    ~NetDec ();

    bool set_default_decoder (const std::string &dec);
    bool input (const byte_t *data, const size_t len,
                const struct timeval &tv, const size_t cap_len = 0);

    // Event
    ev_id lookup_event_id (const std::string &name);
    std::string lookup_event_name (ev_id eid);
    size_t event_size () const;

    // Values
    val_id lookup_value_id (const std::string &name);
    std::string lookup_value_name (val_id pid);
    size_t value_size () const;

    // Decoder
    dec_id lookup_dec_id (const std::string &name);

    // External module
    dec_id load_decoder (const std::string &dec_name, Decoder *dec);
    bool unload_decoder (dec_id d_id);
    bool bind_decoder (dec_id d_id, const std::string &tgt_dec_name);
    bool unbind_decoder (dec_id d_id, const std::string &tgt_dec_name);

    // Handler
    hdlr_id set_handler (ev_id eid, Handler * hdlr);
    hdlr_id set_handler (const std::string ev_name, Handler * hdlr);
    Handler * unset_handler (hdlr_id hid);

    // Timer
    task_id set_onetime_timer (Task *task, int delay_msec);
    task_id set_repeat_timer (Task *task, int interval_msec);
    bool unset_timer (task_id id);

    // Stat
    uint64_t recv_len () const;
    uint64_t cap_len () const;
    uint64_t recv_pkt () const;
    void init_ts (struct timespec *ts) const;
    void last_ts (struct timespec *ts) const;
    double init_ts () const;
    double last_ts () const;


    // Error
    const std::string &errmsg () const;

    // ----------------------------------------------
    // for modules, not used for external program
    ev_id assign_event (const std::string &name, const std::string &desc);
    val_id assign_value (const std::string &name, const std::string &desc,
                           ValueFactory *fac = nullptr);
    void decode (dec_id dec, Property *p);
    void build_value_vector (std::vector <ValueSet *> * prm_vec_);
  };

}  //  namespace swarm

#endif  // SRC_NETDEC_H__
