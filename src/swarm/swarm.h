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

#ifndef SRC_SWARM_H__
#define SRC_SWARM_H__

#include <assert.h>
#include <sys/types.h>
#include <pcap.h>
#include <string>
#include <map>
#include <vector>
#include <deque>

#include "./swarm/common.h"
#include "./swarm/property.h"
#include "./swarm/netdec.h"
#include "./swarm/netcap.h"
#include "./swarm/decode.h"

namespace swarm {
  class NetDec;
  class NetCap;
  class Handler;
  class Task;

  // ----------------------------------------------------------
  // Swarm
  class Swarm {
  protected:
    NetDec *netdec_;
    NetCap *netcap_;
    
  public:
    Swarm();
    ~Swarm();
    hdlr_id set_handler(const std::string &ev_name, Handler *hdlr);
    hdlr_id set_handler(const ev_id eid, Handler *hdlr);
    bool unset_handler(hdlr_id h_id);

    task_id set_periodic_task(Task *task, float interval);
    bool unset_task(task_id t_id);

    ev_id lookup_event_id(const std::string &ev_name) const;
    val_id lookup_value_id(const std::string &val_name) const;

    bool ready() const;
    void start();
    const std::string& errmsg() const;
  };

  class SwarmDev : public Swarm {
  public:
    SwarmDev(const std::string &dev_name);
    ~SwarmDev();
  };
  class SwarmFile : public Swarm {
  public:
    SwarmFile(const std::string &file_path);
    ~SwarmFile();
  };

}

#endif  // SRC_SWARM_H__
