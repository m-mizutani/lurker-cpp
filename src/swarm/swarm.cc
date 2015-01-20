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


#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

#include "./swarm.h"
#include "./debug.h"
#include "./swarm/netdec.h"
#include "./swarm/netcap.h"

namespace swarm {
  Swarm::Swarm() {
    this->netdec_ = new NetDec();    
  };
  Swarm::~Swarm() {
  }

  SwarmDev::SwarmDev(const std::string &dev_name) {
    this->netcap_ = new CapPcapDev(dev_name);
  }
  SwarmDev::~SwarmDev() {
    delete this->netcap_;
  }
  SwarmFile::SwarmFile(const std::string &file_path) {
    this->netcap_ = new CapPcapFile(file_path);
  }
  SwarmFile::~SwarmFile() {
    delete this->netcap_;
  }

  hdlr_id Swarm::set_handler(const std::string &ev_name, Handler *hdlr) {
    return this->netdec_->set_handler(ev_name, hdlr);
  }
  hdlr_id Swarm::set_handler(const ev_id eid, Handler *hdlr) {
    return this->netdec_->set_handler(eid, hdlr);
  }
  bool Swarm::unset_handler(hdlr_id h_id) {
    return this->netdec_->unset_handler(h_id);
  }

  task_id Swarm::set_periodic_task(Task *task, float interval) {
    assert(this->netcap_);
    return this->netcap_->set_periodic_task(task, interval);
  }
  bool Swarm::unset_task(task_id t_id) {
    assert(this->netcap_);
    return this->netcap_->unset_task(t_id);
  }

  ev_id Swarm::lookup_event_id(const std::string &ev_name) const {
    if (this->netdec_) {
      return this->netdec_->lookup_event_id(ev_name);
    } else {
      return EV_NULL;
    }
  }
  val_id Swarm::lookup_value_id(const std::string &val_name) const {
    if (this->netdec_) {
      return this->netdec_->lookup_value_id(val_name);
    } else {
      return VALUE_NULL;
    }
  }

  bool Swarm::ready() const {
    return (this->netcap_ && this->netcap_->ready());
  }

  void Swarm::start() {
    this->netcap_->bind_netdec(this->netdec_);
    this->netcap_->start();
  }

  const std::string& Swarm::errmsg() const {
    return this->netcap_->errmsg();
  }

  Task::Task () {
  }
  Task::~Task () {
  }
  
  // -------------------------------------------------------
  // Handler
  Handler::Handler () {
  }
  Handler::~Handler () {
  }
  
} // namespace swarm
