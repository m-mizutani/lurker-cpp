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

#ifndef SRC_RAWSOCK_H__
#define SRC_RAWSOCK_H__

#include <sstream>

namespace lurker {
  class RawSock {
  private:    
    int sock_;
    std::stringstream err_;
    std::string errmsg_;
    const std::string &dev_name_;
    uint8_t hw_addr_[6];
    uint8_t pr_addr_[4];
    bool hw_addr_set_;
    bool pr_addr_set_;
    static bool get_hw_addr(const std::string &dev_name, uint8_t *hw_addr,
                            size_t len);
    static bool get_pr_addr(const std::string &dev_name, uint8_t *pr_addr,
                            size_t len);
    
  public:
    RawSock(const std::string &dev_name);
    ~RawSock();
    bool open();
    bool ready();
    int write(void *ptr, size_t len);
    const std::string &errmsg();
    const uint8_t* hw_addr() const;
    const uint8_t* pr_addr() const;
  };
}


#endif  // SRC_RAWSOCK_H__
