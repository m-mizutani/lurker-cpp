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

#include "./rawsock.h"
#include <unistd.h>

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

#elif __linux
// linux
#error
#elif __unix // all unices not caught above
// Unix
#error
#elif __posix
// POSIX
#error
#endif


namespace lurker {
  RawSock::RawSock(const std::string &dev_name) : 
    sock_(0),
    dev_name_(dev_name) {
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
    return &(this->hw_addr_[0]);
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

    struct ifaddrs *ifa_list, *ifa; 
    if (getifaddrs(&ifa_list) < 0) {
      this->err_ << "getifaddrs: " << strerror(errno);
    }

    // retrieve MAC address from dev_name
    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
      struct sockaddr_dl *dl = reinterpret_cast<struct sockaddr_dl*> (ifa->ifa_addr);
      if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
        std::string if_name (dl->sdl_data, dl->sdl_nlen);
        if (if_name == this->dev_name_) {
          memcpy (this->hw_addr_, LLADDR(dl), sizeof(this->hw_addr_));
          /*
          printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", if_name.c_str(),
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]); 
          */
          break;
        }
      }
    } 
    freeifaddrs(ifa_list); 

    return true;
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
#error
#elif __unix // all unices not caught above
// Unix
#error
#elif __posix
// POSIX
#error
#endif

}
