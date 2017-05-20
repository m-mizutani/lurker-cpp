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
#include <fluent.hpp>
#include "./rawsock.h"
#include "./target.h"

namespace lurker {
  class TcpHandler {
  private:
    pm::Machine *machine_;
    // swarm::M *sw_;
    /*
    swarm::hdlr_id syn_hdlr_id_;
    swarm::hdlr_id data_hdlr_id_;
    swarm::ev_id syn_ev_;
    swarm::ev_id data_ev_;
    */
    RawSock *sock_;
    static const bool DBG = false;
    const TargetSet *target_;
    fluent::Logger *logger_;
    bool hexdata_log_;
    static size_t build_tcp_synack_packet(const swarm::Property &p,
                                          void *buffer, size_t len);

  public:
    TcpHandler(swarm::Swarm *sw, TargetSet *target);
    ~TcpHandler();
    void set_sock(RawSock *sock);
    void unset_sock();
    void set_logger(fluent::Logger *logger);
    void recv(swarm::ev_id eid, const  swarm::Property &p);
    void handle_synpkt(const swarm::Property &p);
    void handle_data(const swarm::Property &p);

    // Use HEX string in log message instead of binary data.
    void enable_hexdata_log() { this->hexdata_log_ = true; }
    void disable_hexdata_log() { this->hexdata_log_ = false; }
    bool hexdata_log() const { return this->hexdata_log_; }
  };

}


#endif  // SRC_TCP_H__
