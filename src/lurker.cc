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

#include <swarm.h>
#include <fstream>

#include "./lurker.h"
#include "./debug.h"

namespace lurker {
  Lurker::Lurker(const std::string &tgt, bool dry_run) : 
    sw_(NULL), 
    arph_(NULL),
    tcph_(NULL),
    sock_(NULL),
    mq_(NULL),
    dry_run_(dry_run)
  {

    if (!this->dry_run_) {
      this->sw_   = new swarm::SwarmDev(tgt);
      this->sock_ = new RawSock(tgt);
    } else {
      this->sw_ = new swarm::SwarmFile(tgt);
    }

    this->tcph_ = new TcpHandler(this->sw_);
    this->sw_->set_handler("tcp.syn", this->tcph_);

    if (!this->dry_run_) {
      this->tcph_->enable_active_mode();
      this->tcph_->set_sock(this->sock_);
    }
  }
  Lurker::~Lurker() {
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

  void Lurker::enable_arp_spoof() {
    this->arph_ = new ArpHandler(this->sw_);
    // this->arph_->set_mq(mq);
    // arph->set_os(out);
    this->sw_->set_handler("arp.request", this->arph_);

    if (!this->dry_run_) {
      this->arph_->enable_active_mode();
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

  /*
    std::ostream *out = NULL;
    if (opt.is_set("output")) {
      if (opt["output"] == "-") {
        std::cerr << "NOTE: output to stdout" << std::endl;
        out = &std::cout;
      } else {
        std::ofstream *ofs = new std::ofstream();
        ofs->open(opt["output"].c_str(), std::ofstream::out | std::ofstream::app);
        if (!ofs->is_open()) {
          std::cerr << "File open error: " << opt["output"] << std::endl;
          delete ofs;
          return false;
        }
        out = ofs;
      }
    }
  */


