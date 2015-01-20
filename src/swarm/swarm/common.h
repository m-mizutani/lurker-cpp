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

#ifndef SRC_COMMON_H__
#define SRC_COMMON_H__

#include <sys/types.h>

namespace swarm {
  typedef u_int8_t  byte_t;  // 1 byte data type
  typedef int64_t    ev_id;  // Event ID
  typedef int64_t   val_id;  // Value ID
  typedef int64_t  hdlr_id;  // Handler Entry ID
  typedef int64_t  task_id;  // Task ID
  typedef int       dec_id;  // Decoder ID

  const ev_id    EV_NULL = -1;
  const ev_id    EV_BASE =  0;
  const hdlr_id  HDLR_BASE =  0;
  const hdlr_id  HDLR_NULL = -1;
  const val_id   VALUE_NULL = -1;
  const val_id   VALUE_BASE =  0;
  const dec_id   DEC_NULL = -1;
  const dec_id   DEC_BASE =  0;
  const task_id  TASK_NULL = 0;

  class Property;
  class ValueSet;
  class ValueEntry;
  class ValueFactory;
  class Value;
  class Decoder;
  class Task;

  enum FlowDir {
    DIR_NIL = 0, // Not defined
    DIR_L2R, // Left to Right
    DIR_R2L, // Right to Left
  };

}  // namespace swarm

#endif  // SRC_COMMON_H__
