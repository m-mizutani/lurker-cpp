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
#include <iostream>

#include <fluent.hpp>
#include "./lurker.h"
#include "./debug.h"

namespace lurker {
  Lurker::Lurker(const std::string &input, bool dry_run) : 
    sw_(nullptr), 
    spoofer_(nullptr),
    tcph_(nullptr),
    sock_(nullptr),
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
    delete this->spoofer_;
    delete this->sock_;
    delete this->sw_;
    delete this->logger_;
  }

  void Lurker::add_target(const std::string &target) {
    if (!this->target_.insert(target)) {
      throw Exception(this->target_.errmsg());
    }    
  }

  void Lurker::import_target(const std::string &target_file) {
    std::ifstream ifs(target_file);
    std::string buf;
    
    if (ifs.fail()) {
      throw Exception("can not open target file: " + target_file);
    }
    while (getline(ifs, buf)) {
      if (buf.length() > 0) {
        this->add_target(buf);
      }
    }
  }

  void Lurker::output_to_fluentd(const std::string &conf) {
    size_t p = conf.find(":");
    if (p != std::string::npos) {
      const std::string host = conf.substr(0, p);
      const std::string port = conf.substr(p + 1);
      this->logger_->new_forward(host, port);
    } else {
      // conf is just hostname
      this->logger_->new_forward(conf);
    }
  }
  void Lurker::output_to_file(const std::string &fpath) {
    if (fpath == "-") {
      this->logger_->new_dumpfile(1); // Stdout
    } else {
      this->logger_->new_dumpfile(fpath);
    }
  }
  fluent::MsgQueue* Lurker::output_to_queue() {
    return this->logger_->new_msgqueue();
  }

  void Lurker::run() {
    if (this->target_.count() > 0) {
      RawSock *sock = (this->dry_run_ ? nullptr : this->sock_);
      this->spoofer_ = new StaticSpoofer(this->sw_, &this->target_,
                                         this->logger_, sock);
    }
    
    if (!this->sw_->ready()) {
      Exception("not ready");
    }

    this->sw_->start();
  }
}
