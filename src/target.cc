/*-
 * Copyright (c) 2013-2014 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
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

#include "./target.h"
#include <sstream>
#include <assert.h>

namespace lurker {
  TargetSet::TargetSet() : count_(0) {
  }
  TargetSet::~TargetSet() {
    for (auto it = this->target_.begin(); it != this->target_.end(); it++) {
      delete it->second;
    }
  }

  bool TargetSet::insert(const std::string &target) {
    size_t p = target.find(":");
    if (p == std::string::npos) {
      // format is not "<address>:<port>"
      std::stringstream ss;
      ss << "Format of target must be '<address>:<port>' or '<address>:*': " << target;
      this->errmsg_ = ss.str();
      return false;
    }

    // Split string to address and port.
    std::string addr = target.substr(0, p);
    std::string port = target.substr(p + 1);

    // Convert port number to integer.
    char *e;
    bool any_port = true;;
    int port_num = 0;

    if (port != "*") {
      port_num = strtol(port.c_str(), &e, 0);
      any_port = false;

      if (*e != '\0') {
        // port includes not digit chractor
        std::stringstream ss;
        ss << "Port number is not digit: " << port;
        this->errmsg_ = ss.str();
        return false;
      }
    }

    // Insert target address and port number.
    auto it = this->target_.find(addr);
    if (it != this->target_.end() && it->second != nullptr) {
      // Skip if set<int> is nullptr. It means allowing any port.
      (it->second)->insert(port_num);
    } else {
      std::set<int> *port_set = nullptr;
      if (!any_port) {
        port_set = new std::set<int>();
        port_set->insert(port_num);
      }

      this->target_.insert(std::make_pair(addr, port_set));
    }

    this->count_++;
    return true;
  }

  bool TargetSet::has(const std::string &addr) const {
    auto it = this->target_.find(addr);
    return (it != this->target_.end());
  }

  bool TargetSet::has(const std::string &addr, int port) const {
    auto it = this->target_.find(addr);
    if (it != this->target_.end()) {
      if (it->second == nullptr || ((it->second)->find(port) != (it->second)->end())) {
        return true;
      }
    }

    return false;
  }

  const std::string &TargetSet::errmsg() const {
    return this->errmsg_;
  }

}

