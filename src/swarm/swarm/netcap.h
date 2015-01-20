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

#ifndef SRC_NETCAP_H__
#define SRC_NETCAP_H__

// TODO: put include<ev.h> to not installed header or source file.
#include <ev.h>
#include <string>
#include <map>
#include <vector>
#include "./common.h"


namespace swarm {
  class NetDec;
  class Task;
  class TaskEntry;

  // ----------------------------------------------------------------
  // class NetCap:
  // Base class of traffic capture classes. In this version, swarm supports
  // only pcap based capture. However it will support other capture method
  // such as etherpipe (https://github.com/sora/ethpipe).
  //
  class NetCap {
  public:
    enum Status {
      READY = 0,
      RUNNING,
      STOP,
      FAIL,
    };

  private:
    NetDec *nd_;
    std::string errmsg_;
    Status status_;
    struct ev_loop *ev_loop_;
    ev_io watcher_;
    ev_timer timeout_;
    std::map<task_id, TaskEntry*> task_entry_;
    task_id last_id_;

    virtual bool setup() = 0;
    virtual bool teardown() = 0;
    virtual void handler(int revents) = 0;
    static void handle_io_event(EV_P_ struct ev_io *w, int revents);
    static void handle_timeout(EV_P_ struct ev_timer *w, int revents);

  protected:
    inline NetDec *netdec() { return this->nd_; }
    struct ev_loop *ev_loop() const { return this->ev_loop_; }
    void ev_loop_exit();
    void ev_watch_fd(int fd);

    void set_errmsg(const std::string &errmsg);
    void set_status(Status st);

  public:
    explicit NetCap ();
    virtual ~NetCap ();
    void bind_netdec (NetDec *nd);
    inline Status status () const { return this->status_; }
    inline bool ready () const { return (this->status_ == READY); }
    bool start (float timeout = 0);

    task_id set_periodic_task(Task *task, float interval);
    bool unset_task(task_id id);

    const std::string &errmsg () const;
  };

  // ----------------------------------------------------------------
  // class CapPcapMmap:
  // Mmap based fast pcap file reader
  //
  class CapPcapMmap : public NetCap {
  private:
    // From libpcap header
    enum LINKTYPE {
      LINKTYPE_ETHERNET = 1,
      LINKTYPE_RAW = 101,
      LINKTYPE_LINUX_SLL = 113,
    };

    struct pcap_file_hdr {
      uint32_t magic;
      uint16_t version_major;
      uint16_t version_minor;
      int32_t thiszone;
      uint32_t sigfigs;
      uint32_t snaplen;
      uint32_t linktype;
    } hdr_;

    struct pcap_pkt_hdr {
      uint32_t tv_sec;
      uint32_t tv_usec;
      uint32_t caplen;
      uint32_t len;
    };

    int fd_;
    void *addr_;
    uint8_t *base_;
    uint8_t *ptr_;
    uint8_t *eof_;
    size_t length_;

    bool setup();
    bool teardown();
    void handler(int revents);

  public:
    CapPcapMmap(const std::string &filepath);
    ~CapPcapMmap ();
  };

  // ----------------------------------------------------------------
  // class PcapBase:
  // Implemented common pcap functions for CapPcapDev and CapPcapFile
  //
  class PcapBase : public NetCap {
  protected:
    pcap_t *pcap_;
    std::string filter_;
    static const size_t PCAP_BUFSIZE_ = 0xffff;
    static const size_t PCAP_TIMEOUT_ = 1000;
    static const int    PCAP_PROMISC_ = 1;

    bool setup();
    bool teardown();
    void handler(int revents);
    static void handle_pcap_event(EV_P_ struct ev_io *w, int revents);
    static void tick_timer(EV_P_ struct ev_timer *w, int revents);

  public:
    PcapBase ();
    virtual ~PcapBase ();
    bool set_filter (const std::string &filter);
  };

  // ----------------------------------------------------------------
  // class CapPcapDev:
  // Capture live traffic via pcap library from network device
  //
  class CapPcapDev : public PcapBase {
  private:
    std::string dev_name_;

#ifdef __linux__
    // If Linux, PF_PACKET socket instead of pcap interface.
    int sock_fd_;
    u_char *buffer_;
    static const size_t BUFSIZE_ = 0xffff;
    bool setup();
    bool teardown();
    void handler(int revents);
#endif

  public:
    explicit CapPcapDev (const std::string &dev_name);
    ~CapPcapDev ();
    static bool retrieve_device_list(std::vector<std::string> *name_list,
                                     std::string *errmsg);
  };

  // ----------------------------------------------------------------
  // class CapPcapDev:
  // Capture stored traffic via pcap library from file
  //
  class CapPcapFile : public PcapBase {
  private:
    std::string file_path_;

  public:
    explicit CapPcapFile (const std::string &file_path);
    ~CapPcapFile ();
  };

  // ----------------------------------------------------------
  // Task
  class Task {
  protected:
    void stop();
    void exit();

  public:
    Task ();
    virtual ~Task ();
    virtual void exec (const struct timespec &tv) = 0;
  };

  // ----------------------------------------------------------
  // TaskEntry
  class TaskEntry {
  private:
    task_id id_;
    Task *task_;
    float interval_;
    struct ev_loop *loop_;
    struct ev_timer timer_;

  public:
    TaskEntry (task_id id, Task *task, float interval, struct ev_loop *loop);
    ~TaskEntry ();
    task_id id () const { return this->id_; }
    float interval () const { return this->interval_; }
    Task *task () const { return this->task_; }
    static void work (EV_P_ struct ev_timer *w, int revents);
  };


}  //  namespace swarm

#endif  // SRC_NETCAP_H__
