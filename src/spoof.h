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

#ifndef SRC_ARP_H__
#define SRC_ARP_H__

#include <set>
#include <fluent.hpp>
#include "./rawsock.h"
#include "./target.h"

namespace lurker {
  class Spoofer : public swarm::Handler {
  private:
    swarm::Swarm *sw_;
    RawSock *sock_;
    swarm::ev_id req_id_, rep_id_;
    swarm::hdlr_id req_h_, rep_h_;

    virtual void handle_arp_request(const swarm::Property &p) {};
    virtual void handle_arp_reply(const swarm::Property &p) {};
    
  protected:
    fluent::Logger *logger_;
    bool has_sock() const { return (this->sock_ != nullptr); }
    bool write(uint8_t *buf, size_t buf_len, const std::string &ev_name);
    uint8_t *build_arp_reply(const swarm::Property &p, size_t *len);
    void free_arp_reply(uint8_t *ptr);
    
  public:
    Spoofer(swarm::Swarm *sw, fluent::Logger *logger=nullptr,
            RawSock *sock=nullptr);
    ~Spoofer();
    void recv(swarm::ev_id eid, const swarm::Property &p);
  };
  
  class StaticSpoofer : public Spoofer {
  private:
    TargetSet *target_set_;
    void handle_arp_request(const swarm::Property &p);
    void handle_arp_reply(const swarm::Property &p);    

  public:
    StaticSpoofer(swarm::Swarm *sw, TargetSet *target_set,
                  fluent::Logger *logger=nullptr, RawSock *sock=nullptr);
    ~StaticSpoofer();
  };
  
  class DynamicSpoofer : public Spoofer {
  private:
    std::map<std::string, time_t> disg_addrs_; // Disguise addresses
    
    // protected:
    void handle_arp_request(const swarm::Property &p);
    void handle_arp_reply(const swarm::Property &p);
    
  public:
    DynamicSpoofer(swarm::Swarm *sw, fluent::Logger *logger=nullptr,
                   RawSock *sock=nullptr);
    ~DynamicSpoofer();
  };
  
}


#endif  // SRC_ARP_H__
