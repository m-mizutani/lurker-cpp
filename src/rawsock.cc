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

#include "./rawsock.hpp"
#include "./debug.h"
#include <unistd.h>
#include <iostream>

#ifdef _WIN64
//define something for Windows (64-bit)
#error
#elif _WIN32
//define something for Windows (32-bit)
#error
#elif __APPLE__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <errno.h>

#elif __linux
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

#elif __unix // all unices not caught above
// Unix
#error
#elif __posix
// POSIX
#error
#endif


namespace lurker {
  RawSock::RawSock(const std::string &dev_name) : 
    sock_(0), dev_name_(dev_name), hw_addr_set_(false), pr_addr_set_(false) {
    if (!this->open()) {
      std::cerr << this->err_.str() << std::endl;
    }
  }
  RawSock::~RawSock() {
    if (this->sock_ > 0) {
      ::close(this->sock_);
    }
  }

  bool RawSock::ready() {
    if (this->sock_ > 0) {
      return false;
    } else {
      return true;
    }
  }

  const std::string& RawSock::errmsg() {
    this->errmsg_ = this->err_.str();
    this->err_.str("");
    return this->errmsg_;
  }

  const uint8_t* RawSock::hw_addr() const {
    return (this->hw_addr_set_) ? this->hw_addr_ : nullptr;
  }
  const uint8_t* RawSock::pr_addr() const {
    return (this->pr_addr_set_) ? this->pr_addr_ : nullptr;
  }

  bool RawSock::get_pr_addr(const std::string &dev_name, uint8_t *pr_addr,
                            size_t len) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    void * addr =
      static_cast<void*>(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    memcpy(pr_addr, addr, len);
    /*
    char buf[32];
    inet_ntop(AF_INET, addr, buf, sizeof(buf));
    std::cout << "addr: " << buf << std::endl;
    */
    return true;
  }
  

#ifdef _WIN64
//define something for Windows (64-bit)
#error
#elif _WIN32
//define something for Windows (32-bit)
#error
#elif __APPLE__


  bool RawSock::open() {
    int bpf = 0;
    int i = 0;
    for(i = 0; i < 99 && bpf <= 0; i++) {
      std::stringstream bpfdev;
      bpfdev <<  "/dev/bpf" << i;
      bpf = ::open(bpfdev.str().c_str(), O_RDWR);
    }

    if(bpf == -1) {
      this->err_ << "Cannot open any /dev/bpf* device";
      return false;
    }

    this->sock_ = bpf;

    struct ifreq bound_if;
    strncpy(bound_if.ifr_name, this->dev_name_.c_str(), IFNAMSIZ - 1);
    if (ioctl(bpf, BIOCSETIF, &bound_if) > 0) {
      this->err_ << "Cannot bind bpf device to physical device " 
                    << this->dev_name_;
      return false;
    }

    this->hw_addr_set_ =
      RawSock::get_hw_addr(this->dev_name_, this->hw_addr_,
                           sizeof(this->hw_addr_));
    this->pr_addr_set_ = 
      RawSock::get_pr_addr(this->dev_name_, this->pr_addr_,
                           sizeof(this->pr_addr_));
    return true;
  }


  bool RawSock::get_hw_addr(const std::string &dev_name, uint8_t *hw_addr,
                            size_t len) {
    // retrieve MAC address from dev_name
    struct ifaddrs *ifa_list, *ifa; 
    if (getifaddrs(&ifa_list) < 0) {
      std::cerr << "getifaddrs: " << strerror(errno);
      return false;
    }

    bool rc = false;
    
    for (ifa = ifa_list; ifa != nullptr; ifa = ifa->ifa_next) {
      struct sockaddr_dl *dl =
        reinterpret_cast<struct sockaddr_dl*> (ifa->ifa_addr);
      if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
        std::string if_name (dl->sdl_data, dl->sdl_nlen);

        debug(false, "if_name: %s", if_name.c_str());
        if (if_name == dev_name) {
          memcpy (hw_addr, LLADDR(dl), len);
          rc = true;
          /*
          char *addr = LLADDR(dl);
          printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", if_name.c_str(),
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]); 
          */
          break;
        }
      }
    }

    freeifaddrs(ifa_list); 

    return rc;
  }
  
  int RawSock::write(void *ptr, size_t len) {
    int rc;
    rc = ::write(this->sock_, ptr, len);
    if (rc < 0) {
      this->err_ << strerror(errno);
    }

    return rc;
  }

#elif __linux
// linux

  bool RawSock::open() {
    if ((this->sock_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
      this->err_ << "socket: " << strerror(errno);
      return false;
    }

    struct ifreq if_idx, if_mac;
    memset(&if_idx, 0, sizeof(struct ifreq));
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, this->dev_name_.c_str(), IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, this->dev_name_.c_str(), IFNAMSIZ-1);

    debug(false, "bind to %s", if_idx.ifr_name);
    if (ioctl(this->sock_, SIOCGIFINDEX, &if_idx) < 0) {
      this->err_ << "ioctl, SIOCGIFINDEX: " << strerror(errno);
      return false;
    }

    struct sockaddr_ll sa;
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_idx.ifr_ifindex;
    if(bind(this->sock_, (struct sockaddr *)&sa, sizeof(sa)) < 0){
      this->err_ << "bind: " << strerror(errno);
      return false;
    }

      
    debug(false, "obtain MAC address from %s", if_idx.ifr_name);
    if (ioctl(this->sock_, SIOCGIFHWADDR, &if_mac) < 0) {
      this->err_ << "ioctl, SIOCGIFHWADDR: " << strerror(errno);
      return false;
    }

    memcpy (this->hw_addr_, &if_mac.ifr_hwaddr.sa_data, sizeof(this->hw_addr_));
    this->hw_addr_set_ = true;
    this->pr_addr_set_ = 
      RawSock::get_pr_addr(this->dev_name_, this->pr_addr_,
                           sizeof(this->pr_addr_));

    return true;
  }
  int RawSock::write(void *ptr, size_t len) {
    int rc;
    rc = ::write(this->sock_, ptr, len);
    if (rc < 0) {
      this->err_ << "write: " << strerror(errno);
    }

    return rc;
  }

#elif __unix // all unices not caught above
// Unix
#error
#elif __posix
// POSIX
#error
#endif

}
