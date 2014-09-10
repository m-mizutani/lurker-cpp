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

#include <sstream>
#include <string.h>
#include <assert.h>
#include "./emitter.h"

namespace lurker {

  Emitter::Emitter() : zmq_ctx_(NULL), zmq_sock_(NULL) {
  }

  Emitter::~Emitter() {
    if (this->zmq_sock_) {
      zmq_close(this->zmq_sock_);
    }
    if (this->zmq_ctx_) {
      zmq_ctx_destroy(this->zmq_ctx_);
    }
  }

  bool Emitter::open_zmq_pub(int port) {
    this->port_ = port;
    this->zmq_ctx_  = ::zmq_ctx_new();
    this->zmq_sock_ = ::zmq_socket(this->zmq_ctx_, ZMQ_PUSH);
    std::stringstream ss;
    ss << "tcp://*:" << this->port_;
    if (0 != ::zmq_bind(this->zmq_sock_, ss.str().c_str())) {
      this->errmsg_ = ::zmq_strerror(errno);
      return false;
    }

    return true;
  }

  bool Emitter::emit(const msgpack::sbuffer &buf) {
    const void *ptr = buf.data();
    const size_t len = buf.size();

    if (this->zmq_ctx_ && this->zmq_sock_) {
      int rc = ::zmq_send(this->zmq_sock_, ptr, len, 0);
      if (rc < 0) {
        this->errmsg_ = ::zmq_strerror(errno);
        return false;
      }
    }
    return true;
  }

}

