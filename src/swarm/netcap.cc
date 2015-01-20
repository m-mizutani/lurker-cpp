/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp> All
 * rights reserved.
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

#include <sys/time.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <ev.h>
#include <math.h>
#include <string>

#ifdef __linux__
// linux
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#endif  // __linux__

#include "./debug.h"
#include "./swarm/netcap.h"
#include "./swarm/netdec.h"
#include "./swarm/timer.h"


namespace swarm {
  // -------------------------------------------------------------------
  // class NetCap
  //
  NetCap::NetCap () :
    nd_(nullptr), ev_loop_(EV_DEFAULT), last_id_(1) {
  }
  NetCap::~NetCap () {
  }
  void NetCap::bind_netdec (NetDec *nd) {
    this->nd_ = nd;
  }


  bool NetCap::start (float timeout) {
    if (this->status_ != READY) {
      this->set_errmsg("Status is not ready");
      return false;
    }

    if (!this->setup()) {
      return false;
    }

    ev_timer_init(&(this->timeout_), handle_timeout, timeout, 0.);
    this->timeout_.data = this;
    if (timeout > 0.) {
      ev_timer_start(this->ev_loop_, &(this->timeout_));
    }

    ::ev_run(this->ev_loop_, 0);


    if (!this->teardown()) {
      return false;
    }

    if (ev_is_active(&(this->watcher_))) {
      ev_io_stop(this->ev_loop_, &(this->watcher_));
    }
    if (ev_is_active(&(this->timeout_))) {
      ev_timer_stop(this->ev_loop_, &(this->timeout_));
    }
    return true;
  }

  void NetCap::handle_io_event(EV_P_ struct ev_io *w, int revents) {
    NetCap *nc = reinterpret_cast<NetCap*>(w->data);
    debug(false,  "IO_event: %d", revents);
    nc->handler(revents);
  }

  void NetCap::handle_timeout(EV_P_ struct ev_timer *w, int revents) {
    NetCap *nc = reinterpret_cast<NetCap*>(w->data);
    debug(false,  "timeout: %d", revents);
    nc->ev_loop_exit();
  }

  void NetCap::ev_watch_fd(int fd) {
    debug(false,  "watching: %d", fd);
    ev_io_init(&(this->watcher_), NetCap::handle_io_event, fd, EV_READ);
    this->watcher_.data = this;
    ev_io_start(this->ev_loop_, &(this->watcher_));
  }
  void NetCap::ev_loop_exit() {
    debug(false,  "exit");
    // ev_io_stop (EV_A_ w);
    // ev_unloop (this->ev_loop_, EVUNLOOP_ALL);
    ::ev_break(this->ev_loop_, EVBREAK_ALL);
  }




  task_id NetCap::set_periodic_task(Task *task, float interval) {
    TaskEntry *ent = new TaskEntry(this->last_id_, task, interval,
                                   this->ev_loop_);
    this->task_entry_.insert(std::make_pair(ent->id(), ent));
    this->last_id_++;
    return ent->id();
  }
  bool NetCap::unset_task(task_id id) {
    auto it = this->task_entry_.find(id);
    if (this->task_entry_.end() == it) {
      return false;
    } else {
      TaskEntry *ent = it->second;
      this->task_entry_.erase(it->first);
      delete ent;
      return true;
    }
  }

  void NetCap::set_status(Status st) {
    this->status_ = st;
  }
  void NetCap::set_errmsg (const std::string &errmsg) {
    this->errmsg_ = errmsg;
  }
  const std::string &NetCap::errmsg () const {
    return this->errmsg_;
  }


  // -------------------------------------------------------------------
  // class CapPcapMmap
  //
  CapPcapMmap::CapPcapMmap(const std::string &filepath) : fd_(0), addr_(nullptr) {
    assert(0);  // don't use in libev arch
    this->set_status(FAIL);

    this->fd_ = ::open(filepath.c_str(), O_RDONLY);
    if (this->fd_ < 0) {
      this->set_errmsg("can't open file");
      return;
    }

    struct stat buf;
    if (fstat(this->fd_, &buf) != 0) {
      this->set_errmsg("fstat error");
      return;
    }

    this->length_ = buf.st_size;
    if (this->length_ < sizeof(struct pcap_file_hdr)) {
      this->set_errmsg("The file is too short");
      return;
    }

    this->addr_ =
      ::mmap(nullptr, this->length_, PROT_READ, MAP_PRIVATE, this->fd_, 0);
    if (!this->addr_) {
      this->set_errmsg("mmap error");
      return;
    }
    if (0 != madvise(this->addr_, this->length_, MADV_SEQUENTIAL)) {
      this->set_errmsg("madvise error");
      return;
    }

    struct pcap_file_hdr *hdr =
      static_cast<struct pcap_file_hdr *>(this->addr_);

    if (hdr->magic != 0xA1B2C3D4) {
      this->set_errmsg("Invalid pcap magic number");
      return;
    }

    this->base_ = static_cast<uint8_t*>(this->addr_);
    this->eof_  = this->base_ + this->length_;
    this->ptr_  = this->base_ + sizeof(struct pcap_file_hdr);
    ::memcpy(&this->hdr_, hdr, sizeof(this->hdr_));

#if 0
    debug(1, "magic = %08X", hdr->magic);
    debug(1, "ver_major = %u", hdr->version_major);
    debug(1, "ver_minor = %u", hdr->version_minor);
    debug(1, "snaplen = %u", hdr->snaplen);
#endif

    this->set_status(READY);
  }
  CapPcapMmap::~CapPcapMmap() {
    if (this->addr_) {
      ::munmap(this->addr_, this->length_);
    }
    if (this->fd_ != 0) {
      ::close(this->fd_);
    }
  }

  bool CapPcapMmap::setup() {
    // delegate pcap descriptor
    std::string dec = "";
    switch (this->hdr_.linktype) {
    case LINKTYPE_ETHERNET:  dec = "ether"; break;
    case LINKTYPE_RAW:       dec = "ipv4";  break;
    case LINKTYPE_LINUX_SLL: dec = "lcc";   break;
    default:
      this->set_errmsg ("Only DLT_EN10MB and DLT_RAW are "
                        "supported in this version");
      this->set_status (NetCap::FAIL);
      return false;
    }

    std::string err;
    if (this->netdec() && !this->netdec()->set_default_decoder(dec)) {
      this->set_errmsg(this->netdec()->errmsg());
      this->set_status(FAIL);
      return false;
    }

    // ----------------------------------------------
    // processing packets from pcap file
    bool rc = true;
    struct timeval tv;

    while (this->ptr_ < this->eof_) {
#if 0
      debug(1, "PTR: %u", this->ptr_ - this->base_);
      debug(1, "HDR: remain: %u, need: %u", this->eof_ - this->ptr_,
            sizeof(struct pcap_pkt_hdr));
#endif

      if (this->eof_ - this->ptr_ < sizeof(struct pcap_pkt_hdr)) {
        this->set_errmsg("Invalid packet header");
        rc = false;
        break;
      }

      struct pcap_pkt_hdr *pkthdr =
        reinterpret_cast<struct pcap_pkt_hdr*>(this->ptr_);
      this->ptr_ += sizeof(struct pcap_pkt_hdr);
      size_t len = (pkthdr->caplen < pkthdr->len) ?
        pkthdr->caplen : pkthdr->len;

      tv.tv_sec  = pkthdr->tv_sec;
      tv.tv_usec = pkthdr->tv_usec;

#if 0
      debug(1, "DATA: remain: %u, need: %u", this->eof_ - this->ptr_, len);
      debug(1, "TS: %u.%06u", pkthdr->tv_sec, pkthdr->tv_usec);
      debug(1, "CAPLEN: %u, LEN: %u", pkthdr->caplen, pkthdr->len);
#endif

      if (this->eof_ - this->ptr_ < len) {
        this->set_errmsg("Invalid packet data");
        rc = false;
        break;
      }

      uint8_t *pkt_data = this->ptr_;
      this->ptr_ += len;

      if (this->netdec()) {
        this->netdec()->input (pkt_data, pkthdr->len, tv, pkthdr->caplen);
      }
    }

    this->set_status(STOP);
    return rc;
  }

  bool CapPcapMmap::teardown() {
    return true;
  }

  void CapPcapMmap::handler(int revents) {
  }

  // -------------------------------------------------------------------
  // class PcapBase
  //
  PcapBase::PcapBase () : pcap_(nullptr) {
  }
  PcapBase::~PcapBase () {
  }
  bool PcapBase::set_filter (const std::string &filter) {
    if (this->pcap_ == nullptr) {
      this->set_errmsg("Can't apply filter to unavailable device/file");
      return false;
    }

    if (!filter.empty ()) {
      struct bpf_program fp;
      bpf_u_int32 net  = 0;
      bpf_u_int32 mask = 0;

      /*
      if (pcap_lookupnet(dev.c_str (), &net, &mask, errbuf) == -1) {
        net = 0;
      }
      */

      if (pcap_compile (this->pcap_, &fp, filter.c_str (), net, mask) < 0 ||
          pcap_setfilter (this->pcap_, &fp) == -1) {
        std::string err;
        err = "filter compile/set error: ";
        err += pcap_geterr (this->pcap_);
        err += " \"" + filter + "\"";
        this->set_errmsg (err);
        return false;
      }

      this->filter_ = filter;
    }

    return true;
  }

  bool PcapBase::setup () {
    // delegate pcap descriptor
    int dlt = pcap_datalink (this->pcap_);
    std::string dec = "";
    switch (dlt) {
    case DLT_EN10MB: dec = "ether"; break;
    case DLT_RAW:    dec = "ipv4";  break;
    case DLT_LINUX_SLL: dec = "lcc"; break;
    default:
      this->set_errmsg ("Only DLT_EN10MB and DLT_RAW are "
                        "supported in this version");
      this->set_status (NetCap::FAIL);
      return false;
    }

    std::string err;
    if (this->netdec() && !this->netdec()->set_default_decoder(dec)) {
      this->set_errmsg(this->netdec()->errmsg());
      this->set_status(FAIL);
      return false;
    }

    // ----------------------------------------------
    // processing packets from pcap file
    this->ev_watch_fd(::pcap_get_selectable_fd(this->pcap_));
    return true;
  }

  bool PcapBase::teardown() {
    pcap_close (this->pcap_);
    this->pcap_ = nullptr;
    return true;
  }


  void PcapBase::handler(int revents) {
    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    int rc;
    // debug(true, "event: %d", revents);
    for(int i = 0; i < 12; i++) {
      pkt_data = nullptr;
      rc = ::pcap_next_ex (this->pcap_, &pkthdr, &pkt_data);

      if (rc == 1 && this->netdec()) {
        this->netdec()->input (pkt_data, pkthdr->len, pkthdr->ts,
                               pkthdr->caplen);
      } else if (rc < 0) {
        this->ev_loop_exit();
        return;
      } else {
        return;
      }
    }
  }


  // -------------------------------------------------------------------
  // class CapPcapDev
  //
  CapPcapDev::CapPcapDev (const std::string &dev_name) :
    dev_name_(dev_name) {
    this->set_status (NetCap::FAIL);
    
#ifdef __linux__
    this->sock_fd_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this->sock_fd_ < 0) {
      this->set_errmsg (strerror(errno));
      return;
    }

    struct ifreq if_idx, if_mac, if_prom;
    memset(&if_idx, 0, sizeof(struct ifreq));
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, this->dev_name_.c_str(), IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, this->dev_name_.c_str(), IFNAMSIZ-1);

    // Bind interface.
    if (ioctl(this->sock_fd_, SIOCGIFINDEX, &if_idx) < 0) {
      this->set_errmsg(strerror(errno));
      return;
    }

    // Set promiscous mode.
    memset(&if_prom, 0, sizeof(if_prom));
    strncpy(if_prom. ifr_name, this->dev_name_.c_str(), IFNAMSIZ-1);
    ioctl(this->sock_fd_, SIOCGIFFLAGS, &if_prom);
    if_prom.ifr_flags|=IFF_PROMISC;
    ioctl(this->sock_fd_, SIOCSIFFLAGS, &if_prom);

    // Set non-blocking mode.
    int val = 1;
    ioctl(this->sock_fd_, FIONBIO, &val);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_idx.ifr_ifindex;
    if(bind(this->sock_fd_, (struct sockaddr *)&sa, sizeof(sa)) < 0){
      this->set_errmsg(strerror(errno));
      return;
    }
    
#else  // __linux__    
    char errbuf[PCAP_ERRBUF_SIZE];

    this->pcap_ = pcap_open_live (this->dev_name_.c_str (), PCAP_BUFSIZE_,
                                  PCAP_PROMISC_, 10, errbuf);
    // open interface
    if (nullptr == this->pcap_) {
      this->set_errmsg (errbuf);
      this->set_status (NetCap::FAIL);
    }

#endif  // __linux__

    this->set_status (NetCap::READY);
  }
  CapPcapDev::~CapPcapDev () {
  }



#ifdef __linux__

  bool CapPcapDev::setup() {
    // delegate pcap descriptor
    static const std::string dec = "ether";

    if (this->netdec() && !this->netdec()->set_default_decoder(dec)) {
      this->set_errmsg(this->netdec()->errmsg());
      this->set_status(FAIL);
      return false;
    }

    this->buffer_ = new u_char[BUFSIZE_];

    for(;;) {
      // Flush socket buffer.
      fd_set fds;
      struct timeval t;
      FD_ZERO(&fds);  
      FD_SET(this->sock_fd_, &fds);
      memset(&t, 0, sizeof(t));
      int rc = select(FD_SETSIZE, &fds, nullptr, nullptr, &t);
      if (rc > 0) {
        recv(this->sock_fd_, this->buffer_, BUFSIZE_, 0);
      } else {
        break;
      }
    }

    // ----------------------------------------------
    // processing packets from pcap file
    this->ev_watch_fd(this->sock_fd_);
    return true;
  }
  bool CapPcapDev::teardown() {
    ::close(this->sock_fd_);
    delete this->buffer_;
    return true;
  }
  void CapPcapDev::handler(int revents) {
    int rc;

    struct timeval tv;

    for(int i = 0; i < 16; i++) {
      rc = ::recv(this->sock_fd_, this->buffer_, BUFSIZE_, 0);
      if (rc > 0) {
        gettimeofday(&tv, nullptr);
        this->netdec()->input (this->buffer_, rc, tv);
      } else {
        return;
      }
    }
  }
#endif  // __linux__

  bool CapPcapDev::retrieve_device_list(std::vector<std::string> *name_list,
                                        std::string *errmsg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    if (0 == pcap_findalldevs(&alldevsp, errbuf)) {
      pcap_if_t *dev;
      for(dev = alldevsp; dev; dev = dev->next) {
        name_list->push_back(std::string(dev->name));
      }
      pcap_freealldevs(alldevsp);
      return true;
    } else {
      errmsg->assign(errbuf);
      return false;
    }
  }


  // -------------------------------------------------------------------
  // class CapPcapFile
  //
  CapPcapFile::CapPcapFile (const std::string &file_path) :
    file_path_(file_path) {
    char errbuf[PCAP_ERRBUF_SIZE];

    this->pcap_ = ::pcap_open_offline(this->file_path_.c_str (), errbuf);
    if (this->pcap_ == nullptr) {
      this->set_errmsg (errbuf);
      this->set_status (NetCap::FAIL);
    } else {
      this->set_status (NetCap::READY);
    }
  }
  CapPcapFile::~CapPcapFile () {
  }

  TaskEntry::TaskEntry (task_id id, Task *task, float interval,
                        struct ev_loop *loop) :
    id_(id), task_(task), interval_(interval), loop_(loop) {
    this->timer_.data = this;
    ev_timer_init(&(this->timer_), TaskEntry::work, 0.0, this->interval_);
    ev_timer_start(this->loop_, &(this->timer_));
  }
  TaskEntry::~TaskEntry () {
    ev_timer_stop(this->loop_, &(this->timer_));
  }
  void TaskEntry::work(EV_P_ struct ev_timer *w, int revents) {
    TaskEntry *ent = reinterpret_cast<TaskEntry*>(w->data);
    double tv = ev_now(EV_A);
    double tv_sec, tv_nsec;
    struct timespec ts;
    tv_nsec = modf(tv, &tv_sec);
    ts.tv_sec  = static_cast<time_t>(tv_sec);
    ts.tv_nsec = static_cast<long>(tv_nsec * 1e+9);
    ent->task_->exec(ts);
  };

}  // namespace swarm
