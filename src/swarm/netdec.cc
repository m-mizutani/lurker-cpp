/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp> All
 * rights reserved.
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

#include <string.h>
#include <sys/time.h>

#include "./swarm/netdec.h"
#include "./swarm/property.h"
#include "./swarm/decode.h"
#include "./swarm/timer.h"
#include "./debug.h"

namespace swarm {
  // -------------------------------------------------------
  // HandlerEntry

  HandlerEntry::HandlerEntry (hdlr_id hid, ev_id ev, Handler * hdlr) :
    id_(hid), ev_(ev), hdlr_(hdlr) {
  }
  HandlerEntry::~HandlerEntry () {
  }
  Handler * HandlerEntry::hdlr () const {
    return this->hdlr_;
  }
  hdlr_id HandlerEntry::id () const {
    return this->id_;
  }
  ev_id HandlerEntry::ev () const {
    return this->ev_;
  }


  // -------------------------------------------------------
  // NetDec
  NetDec::NetDec () :
    base_did_(DEC_BASE),
    base_eid_(EV_BASE),
    base_vid_(VALUE_BASE),
    base_hid_(HDLR_BASE),
    none_(""),
    recv_len_(0),
    cap_len_(0),
    recv_pkt_(0) {
    this->init_ts_.tv_sec = 0;;
    this->init_ts_.tv_nsec = 0;;
    this->last_ts_.tv_sec = 0;;
    this->last_ts_.tv_nsec = 0;;

    std::vector <Decoder *> mod_array;
    std::vector <std::string> name_array;

    size_t mod_count =
      DecoderMap::build_decoder_vector (this, &mod_array, &name_array);
    for (size_t i = 0; i < mod_count; i++) {
      dec_id d_id = this->install_dec_mod (name_array[i], mod_array[i]);
      assert (d_id != DEC_NULL);
    }

    for (size_t n = 0; n < mod_count; n++) {
      this->dec_mod_[n]->setup (this);
    }

    this->dec_default_ = this->lookup_dec_id ("ether");
    assert (this->dec_default_ != DEC_NULL);
    // this->prop_ = new Property (this);
  }
  NetDec::~NetDec () {
    for (auto it = this->rev_event_.begin ();
         it != this->rev_event_.end (); it++) {
      size_t i = static_cast<size_t> (it->first - EV_BASE);
      delete this->event_handler_[i];
    }

    this->fwd_dec_.clear ();
    this->rev_dec_.clear ();
  }

  dec_id NetDec::install_dec_mod (const std::string &name, Decoder *dec) {
    dec_id d_id = this->base_did_;
    this->base_did_++;
    if (this->dec_mod_.size() < d_id + 1) {
      this->dec_mod_.resize (d_id + 1);
      this->dec_mod_[d_id] = nullptr;
      this->dec_bind_.resize (d_id + 1);
    }

    if (this->fwd_dec_.find (name) != this->fwd_dec_.end ()) {
      this->errmsg_ = "duplicated decoder name: " + name;
      return DEC_NULL;
    }

    this->fwd_dec_.insert (std::make_pair (name, d_id));
    this->rev_dec_.insert (std::make_pair (d_id, name));
    this->dec_mod_[d_id] = dec;
    return d_id;
  }

  Decoder *NetDec::uninstall_dec_mod (dec_id d_id) {
    auto rit = this->rev_dec_.find (d_id);
    if (rit == this->rev_dec_.end ()) {
      this->errmsg_ = "no avaialable decoder id";
      return nullptr;
    }
    std::string name = rit->second;
    this->rev_dec_.erase (rit);

    auto fit = this->fwd_dec_.find (name);
    assert (fit != this->fwd_dec_.end ());
    this->fwd_dec_.erase (fit);
    
    assert (d_id < this->dec_mod_.size ());
    Decoder * dec = this->dec_mod_[d_id];
    assert (nullptr != dec);
    this->dec_mod_[d_id] = nullptr;
    return dec;
  }


  bool NetDec::set_default_decoder (const std::string &dec_name) {
    dec_id d_id = this->lookup_dec_id (dec_name);
    if (d_id != DEC_NULL) {
      this->dec_default_ = d_id;
      return true;
    } else {
      return false;
    }
  }
  bool NetDec::input (const byte_t *data, const size_t len,
                      const struct timeval &tv, const size_t cap_len) {
    // If cap_len == 0, actual captured length is same with real packet length
    size_t c_len = (cap_len == 0) ? len : cap_len;

    // update stat information
    if (this->init_ts_.tv_sec == 0) {
      this->init_ts_.tv_sec = tv.tv_sec;
      this->init_ts_.tv_nsec = tv.tv_usec * 1000;
      this->prop_ = new Property (this);
    }

    // main process of NetDec
    Property * prop = this->prop_;

    this->recv_pkt_ += 1;
    this->recv_len_ += len;
    this->cap_len_ += c_len;
    this->last_ts_.tv_sec = tv.tv_sec;
    this->last_ts_.tv_nsec = tv.tv_usec * 1000;

    // Initialize property with packet data
    // NOTE: memory of data must be secured in this function because of
    //       zero-copy impolementation.
    prop->init (data, c_len, len, tv);

    // emit to decoder
    this->decode (this->dec_default_, prop);

    // calculate hash value of 5 tuple
    prop->calc_hash ();

    // execute callback function of handler
    ev_id eid;
    while (EV_NULL != (eid = prop->pop_event ())) {
      assert (0 <= eid);
      assert (eid < static_cast<ev_id>(this->event_handler_.size ()));

      auto hdlr_list = this->event_handler_[eid];
      if (hdlr_list) {
        for (auto it = hdlr_list->begin (); it != hdlr_list->end (); it++) {
          Handler * hdlr = (*it)->hdlr ();
          assert (hdlr != nullptr);
          hdlr->recv (eid, *prop);
        }
      }
    }

    // handle timer
    // this->timer_->ticktock (tv);

    return true;
  }

  // -------------------------------------------------------------------------------
  // NetDec Event
  //
  ev_id NetDec::lookup_event_id (const std::string &name) {
    auto it = this->fwd_event_.find (name);
    return (it != this->fwd_event_.end ()) ? it->second : EV_NULL;
  }

  std::string NetDec::lookup_event_name (ev_id eid) {
    auto it = this->rev_event_.find (eid);
    return (it != this->rev_event_.end ()) ? it->second : this->none_;
  }
  size_t NetDec::event_size () const {
    assert (this->base_eid_ >= 0);
    assert (this->base_eid_ == static_cast<ev_id>(this->fwd_event_.size ()));
    return this->fwd_event_.size ();
  }

  // -------------------------------------------------------------------------------
  // NetDec Value
  //
  std::string NetDec::lookup_value_name (val_id vid) {
    auto it = this->rev_value_.find (vid);
    if (it != this->rev_value_.end ()) {
      return (it->second)->name ();
    } else {
      return this->none_;
    }
  }
  val_id NetDec::lookup_value_id (const std::string &name) {
    auto it = this->fwd_value_.find (name);
    return (it != this->fwd_value_.end ()) ? (it->second)->vid () : VALUE_NULL;
  }
  size_t NetDec::value_size () const {
    assert (this->base_vid_ >= 0);
    assert (this->base_vid_ == static_cast<ev_id>(this->fwd_value_.size ()));
    return this->fwd_value_.size ();
  }

  // -------------------------------------------------------------------------------
  // NetDec Decoder
  //
  dec_id NetDec::lookup_dec_id (const std::string &name) {
    auto it = this->fwd_dec_.find (name);
    if (it != this->fwd_dec_.end ()) {
      return it->second;
    } else {
      return DEC_NULL;
    }
  }

  dec_id NetDec::load_decoder (const std::string &dec_name, Decoder *dec) {
    dec_id d_id = this->install_dec_mod (dec_name, dec);
    if (d_id != DEC_NULL) {
      dec->setup (this);
    }
    return d_id;
  }
  bool NetDec::unload_decoder (dec_id d_id) {    
    return (nullptr != this->uninstall_dec_mod (d_id));
  }
  bool NetDec::bind_decoder (dec_id d_id, const std::string &tgt_dec_name) {
    auto it = this->fwd_dec_.find (tgt_dec_name);
    if (it == this->fwd_dec_.end ()) {
      this->errmsg_ = "no such decoder name: " + tgt_dec_name;
      return false;
    }

    dec_id tgt_id = it->second;
    assert (tgt_id < this->dec_bind_.size ());
    auto t_it = this->dec_bind_[tgt_id].find (d_id);
    if (t_it != this->dec_bind_[tgt_id].end ()) {
      this->errmsg_ = "already bound decoder";
      return false;
    }

    this->dec_bind_[tgt_id].insert (std::make_pair (d_id, d_id));
    return true;
  }
  bool NetDec::unbind_decoder (dec_id d_id, const std::string &tgt_dec_name) {
    auto it = this->fwd_dec_.find (tgt_dec_name);
    if (it == this->fwd_dec_.end ()) {
      this->errmsg_ = "no such decoder name: " + tgt_dec_name;
      return false;
    }

    dec_id tgt_id = it->second;
    assert (tgt_id < this->dec_bind_.size ());
    auto t_it = this->dec_bind_[tgt_id].find (d_id);
    if (t_it == this->dec_bind_[tgt_id].end ()) {
      this->errmsg_ = "no available bind";
      return false;
    }

    this->dec_bind_[tgt_id].erase (t_it);
    return true;
  }


  // -------------------------------------------------------------------------------
  // NetDec Handler
  //

  hdlr_id NetDec::set_handler (ev_id eid, Handler * hdlr) {
    const size_t idx = NetDec::eid2idx (eid);
    if (eid < EV_BASE || this->event_handler_.size () <= idx) {
      return HDLR_NULL;
    } else {
      hdlr_id hid = this->base_hid_++;
      HandlerEntry * ent = new HandlerEntry (hid, eid, hdlr);
      this->event_handler_[idx]->push_back (ent);
      auto p = std::make_pair (hid, ent);
      this->rev_hdlr_.insert (p);
      return hid;
    }
  }

  hdlr_id NetDec::set_handler (const std::string ev_name, Handler * hdlr) {
    auto it = this->fwd_event_.find (ev_name);
    if (it == this->fwd_event_.end ()) {
      return HDLR_NULL;
    } else {
      return this->set_handler (it->second, hdlr);
    }
  }

  Handler * NetDec::unset_handler (hdlr_id entry) {
    auto it = this->rev_hdlr_.find (entry);
    if (it == this->rev_hdlr_.end ()) {
      return nullptr;
    } else {
      HandlerEntry * ent = it->second;
      this->rev_hdlr_.erase (it);
      size_t idx = NetDec::eid2idx (ent->ev ());
      auto dq = this->event_handler_[idx];
      for (auto dit = dq->begin (); dit != dq->end (); dit++) {
        if ((*dit)->id () == ent->id ()) {
          dq->erase (dit);
          break;
        }
      }
      Handler * hdlr = ent->hdlr ();
      delete ent;
      return hdlr;
    }
  }

  uint64_t NetDec::recv_len () const {
    return this->recv_len_;
  }
  uint64_t NetDec::cap_len () const {
    return this->cap_len_;
  }
  uint64_t NetDec::recv_pkt () const {
    return this->recv_pkt_;
  }
  void NetDec::init_ts (struct timespec *ts) const {
    memcpy (ts, &(this->init_ts_), sizeof (struct timespec));
  }
  void NetDec::last_ts (struct timespec *ts) const {
    memcpy (ts, &(this->init_ts_), sizeof (struct timespec));
  }
  double NetDec::init_ts () const {
    return static_cast<double> (this->init_ts_.tv_sec) +
      static_cast<double> (this->init_ts_.tv_nsec) / (1000 * 1000 * 1000);
  }
  double NetDec::last_ts () const {
    return static_cast<double> (this->last_ts_.tv_sec) +
      static_cast<double> (this->last_ts_.tv_nsec) / (1000 * 1000 * 1000);
  }



  const std::string &NetDec::errmsg () const {
    return this->errmsg_;
  }


  ev_id NetDec::assign_event (const std::string &name,
                              const std::string &desc) {
    if (this->fwd_event_.end () != this->fwd_event_.find (name)) {
      return EV_NULL;
    } else {
      const ev_id eid = this->base_eid_;
      this->fwd_event_.insert (std::make_pair (name, eid));
      this->rev_event_.insert (std::make_pair (eid, name));

      const size_t idx = NetDec::eid2idx (eid);
      if (this->event_handler_.size () <= idx) {
        this->event_handler_.resize (idx + 1);
      }
      this->event_handler_[idx] = new std::deque <HandlerEntry *> ();

      this->base_eid_++;
      return eid;
    }
  }
  val_id NetDec::assign_value (const std::string &name,
                                 const std::string &desc, ValueFactory * fac) {
    if (this->fwd_value_.end () != this->fwd_value_.find (name)) {
      return VALUE_NULL;
    } else {
      const val_id vid = this->base_vid_;

      ValueEntry * ent = new ValueEntry (vid, name, desc, fac);
      this->fwd_value_.insert (std::make_pair (name, ent));
      this->rev_value_.insert (std::make_pair (vid,  ent));
      this->base_vid_++;
      return vid;
    }
  }

  void NetDec::decode (dec_id dec, Property *p) {
    assert (0 <= dec && dec < static_cast<dec_id>(this->dec_mod_.size ()));
    if (this->dec_mod_[dec]) {
      bool rc = this->dec_mod_[dec]->decode (p);

      if (rc && this->dec_bind_[dec].size () > 0) {
        for (auto it = this->dec_bind_[dec].begin ();
             it != this->dec_bind_[dec].end (); it++) {
          Decoder * dec = this->dec_mod_[it->first];
          if (dec && dec->accept (*p)) {
            dec->decode (p);
          }
        }
      }
    }
  }

  void NetDec::build_value_vector (std::vector <ValueSet *> * val_vec_) {
    val_vec_->resize (this->value_size ());

    for (auto it = this->fwd_value_.begin ();
         it != this->fwd_value_.end (); it++) {
      ValueEntry * ent = it->second;
      debug (0, "name: %s, %s", ent->name().c_str (), ent->desc().c_str ());
      size_t idx = Property::vid2idx (ent->vid ());
      assert (idx < val_vec_->size ());
      (*val_vec_)[idx] = new ValueSet (ent->fac ());
    }
  }
}  // namespace swarm
