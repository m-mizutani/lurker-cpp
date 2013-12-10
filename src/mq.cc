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

#include "./mq.h"
#include <zmq.h>
#include <assert.h>

namespace lurker {
  MsgQueue::MsgQueue(int port) : port_(port), ctx_(NULL), pub_(NULL) {
    this->ctx_ = zmq_ctx_new ();
    this->pub_ = zmq_socket (this->ctx_, ZMQ_PUB);

    std::stringstream ss;
    ss <<  "tcp://*:" << this->port_;
    int rc = zmq_bind (this->pub_, ss.str().c_str());
    assert (rc == 0);
  }
  MsgQueue::~MsgQueue() {
    if (this->pub_) {
      zmq_close(this->pub_);
    }
    if (this->ctx_) {
      zmq_ctx_destroy(this->ctx_);
    }
  }
  
  bool MsgQueue::push(const std::map<std::string, std::string> &msg) {
    /* Create a new message, allocating 6 bytes for message content */
    zmq_msg_t m;
    int rc = zmq_msg_init_size (&m, 6);
    assert (rc == 0);
    /* Fill in message content with 'AAAAAA' */
    memset (zmq_msg_data (&m), 'A', 6);
    /* Send the message to the socket */
    rc = zmq_send (this->pub_, &m, 0, ZMQ_SNDMORE); 
    assert (rc == 0);

    return true;
  }

}
