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
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <fstream>

#include <fluent.hpp>
#include "./lurker.h"
#include "./debug.h"

namespace lurker {
  Lurker::Lurker(const std::string &input, bool dry_run) : 
    sw_(NULL), 
    arph_(NULL),
    tcph_(NULL),
    sock_(NULL),
    dry_run_(dry_run),
    logger_(nullptr)
  {
    // Create Logger
    this->logger_ = new fluent::Logger();
      
    // Create Swarm instance
    if (!this->dry_run_) {
      this->sw_   = new swarm::SwarmDev(input);
      this->sock_ = new RawSock(input);
    } else {
      this->sw_ = new swarm::SwarmFile(input);
    }

    this->tcph_ = new TcpHandler(this->sw_, &this->target_);
    this->tcph_->set_logger(this->logger_);
    
    if (!this->dry_run_) {
      this->tcph_->set_sock(this->sock_);
    }
  }
  Lurker::~Lurker() {
    delete this->tcph_;
    delete this->arph_;
    delete this->sock_;
    delete this->sw_;
    delete this->logger_;
  }

  void Lurker::set_filter(const std::string &filter) {
    /*
    if (!this->sw_->set_filter(filter)) {
      std::string err = "Pcap filter error: ";
      err += pcap_dev->errmsg();
      throw new Exception(err);
    }
    */
  }


  void Lurker::add_target(const std::string &target) throw(Exception) {
    if (!this->target_.insert(target)) {
      throw Exception(this->target_.errmsg());
    }    
  }

  void Lurker::enable_arp_spoof() {
    this->arph_ = new ArpHandler(this->sw_, &this->target_, &this->emitter_);
    // this->arph_->set_mq(mq);
    // arph->set_os(out);
    this->sw_->set_handler("arp.request", this->arph_);

    if (!this->dry_run_) {
      this->arph_->set_sock(this->sock_);
    }
  }

  void Lurker::run() throw(Exception) {
    if (!this->sw_->ready()) {
      Exception("not ready");
    }

    this->sw_->start();
  }
}
