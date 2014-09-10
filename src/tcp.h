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

#ifndef SRC_TCP_H__
#define SRC_TCP_H__

#include <sstream>
#include <ostream>
#include <swarm.h>
#include "./rawsock.h"
#include "./emitter.h"
#include "./target.h"

namespace lurker {
  class TcpHandler : public swarm::Handler {
  private:
    swarm::Swarm *sw_;
    swarm::hdlr_id hdlr_id_;
    RawSock *sock_;
    static const bool DBG = false;
    const TargetSet *target_;
    Emitter *emitter_;
    std::ostream *out_;

    static size_t build_tcp_synack_packet(const swarm::Property &p,
                                          void *buffer, size_t len);

  public:
    TcpHandler(swarm::Swarm *sw, TargetSet *target, Emitter *emitter);
    ~TcpHandler();
    void set_sock(RawSock *sock);
    void unset_sock();
    void set_out_stream(std::ostream *os);
    void unset_out_stream();
    void recv(swarm::ev_id eid, const  swarm::Property &p);
  };

}


#endif  // SRC_TCP_H__
