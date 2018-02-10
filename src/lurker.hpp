/*
 * Copyright (c) 2014 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
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

#ifndef SRC_LURKER_H__
#define SRC_LURKER_H__

#include <sstream>
#include <ostream>

#include "./target.hpp"

namespace fluent {
class Logger;
class MsgQueue;
}
namespace pm {
class Machine;
}

namespace lurker {
class Spoofer;
class RawSock;

class Exception : public std::exception {
 private:
  std::string errmsg_;
 public:
  Exception(const std::string &errmsg) : errmsg_(errmsg) {}
  ~Exception() {}
  virtual const char* what() const throw() { return this->errmsg_.c_str(); }
};

class Lurker {
 private:
  Spoofer *spoofer_;
  // TcpHandler *tcph_;
  fluent::Logger *logger_;
  TargetSet target_;
  std::string source_name_;

  virtual void setup() = 0;
  
 protected:
  const TargetSet& targets() const { return this->target_; }
  const std::string& source_name() const { return this->source_name_; }
  pm::Machine *machine_;

 public:
  Lurker(const std::string &source_name);
  virtual ~Lurker();

  // configure reply target
  void add_target(const std::string &target);
  void import_target(const std::string &target_file);
  bool has_target() const { return (this->target_.count() > 0); }

  // configure output
  void output_to_fluentd(const std::string &conf);
  void output_to_file(const std::string &fpath);
  fluent::MsgQueue* output_to_queue();

  // Use HEX string in log message instead of binary data.
  /*
  void enable_hexdata_log() { this->tcph_->enable_hexdata_log(); }
  void disable_hexdata_log() { this->tcph_->disable_hexdata_log(); }
  bool hexdata_log() const { return this->tcph_->hexdata_log(); }
  */
  
  void run();
};


class DryRun : public Lurker {
 private:
  void setup();

 public:
  DryRun(const std::string& src);
  ~DryRun();
};


class Device : public Lurker {
 private:
  RawSock *sock_;
  void setup();
  
 public:
  Device(const std::string& src);
  ~Device();
};

}

#endif   // SRC_LURKER_H__
