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
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <swarm.h>
#include <fstream>

#include "./debug.h"
#include "./optparse.h"
#include "./rawsock.h"
#include "./arp.h"
#include "./tcp.h"
#include "./mq.h"

namespace lurker {
  swarm::NetCap *setup_netcap(const optparse::Values& opt) {
    // prepare network capturing instance
    swarm::NetCap *ncap = NULL;
    const std::string filter = opt["filter"];

    if (opt.is_set("interface")) {
      const std::string dev_name = opt["interface"];
      swarm::CapPcapDev *pcap_dev = new swarm::CapPcapDev(dev_name);

      if (!pcap_dev->set_filter(filter)) {
        std::cerr << "Pcap filter error: " << pcap_dev->errmsg() << std::endl;
        return NULL;
      }

      ncap = pcap_dev;
    } else if (opt.is_set("pcap_file")) {
      swarm::CapPcapFile *pcap_file = new swarm::CapPcapFile(opt["pcap_file"]);

      if (!pcap_file->set_filter(filter)) {
        std::cerr << "Pcap filter error: " << pcap_file->errmsg() << std::endl;
        return NULL;
      }

      ncap = pcap_file;
    }

    if (!ncap) {
      std::cerr << "Network interface must be specified" << std::endl;
      return NULL;
    }
    
    return ncap;
  }

  bool main(const optparse::Values& opt,
            const std::vector <std::string> args) {
    // prepare network decoder instance
    swarm::NetDec nd;
    ArpHandler *arph = NULL;
    TcpHandler *tcph = NULL;
    TargetRep *tgt_rep = NULL;

    // setup NetCap (Open network interface or pcap file)
    swarm::NetCap *ncap = setup_netcap(opt);
    if (!ncap) {
      return false;
    }

    RawSock *sock = NULL;    
    OutputQueue *mq = NULL;

    if (opt.is_set("interface")) {
      sock = new RawSock(opt["interface"]);
    }

    if (opt.is_set("publish")) {
      char *e;
      unsigned int port = strtoul(opt["publish"].c_str(), &e, 0);
      if (*e != '\0' || port <= 0 || 65355 <= port) {
        std::cerr << 
          "publish(-p) option should be number, and 0 < port < 65355: " << 
          opt["publish"] << std::endl;
        return false;
      }
      mq = new ZmqPub(port);
    }

    std::ostream *out = NULL;
    if (opt.is_set("output")) {
      if (opt["output"] == "-") {
        std::cerr << "NOTE: output to stdout" << std::endl;
        out = &std::cout;
      } else {
        std::ofstream *ofs = new std::ofstream();
        ofs->open(opt["output"].c_str(), std::ofstream::out | std::ofstream::app);
        if (!ofs->is_open()) {
          std::cerr << "File open error: " << opt["output"] << std::endl;
          delete ofs;
          return false;
        }
        out = ofs;
      }
    }

    arph = new ArpHandler(&nd);
    arph->set_mq(mq);
    arph->set_os(out);
    nd.set_handler("arp.request", arph);

    tcph = new TcpHandler(&nd);
    tcph->set_mq(mq);
    tcph->set_os(out);
    nd.set_handler("tcp.syn", tcph);

    if (opt.is_set("target")) {
      // Activate arp spoof mode
      arph->enable_active_mode();
      arph->set_sock(sock);
      // Activate tcp dummy syn-ack response mode
      tcph->enable_active_mode();
      tcph->set_sock(sock);

      tgt_rep = new TargetRep();
      // Insert target data to AprHandler and TcpHandler
      for (auto it = opt.all("target").begin(); 
           it != opt.all("target").end(); it++) {
        if (!tgt_rep->insert(*it)) {
          std::cerr << tgt_rep->errmsg() << std::endl;
          return false;
        }
      }

      arph->set_target(tgt_rep); 
      tcph->set_target(tgt_rep);
    }

    // start process
    ncap->bind_netdec(&nd);
    if (!ncap->ready() || !ncap->start()) {
      std::cerr << ncap->errmsg() << std::endl;
      return false;
    }

    // clean up
    if (out != &std::cout) {
      delete out;
    }

    return true;
  }
}

int main(int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");
  psr.add_option("-r").dest("pcap_file")
    .help("Specify pcap_file, read operation only");
  psr.add_option("-t").dest("target").action("append")
    .help("Target for TCP response, format) address:port");
  psr.add_option("-f").dest("filter")
    .help("Filter");
  psr.add_option("-p").dest("publish").metavar("INT")
    .help("Publishing result as message queue, should provide zmq port number");
  psr.add_option("-o").dest("output").metavar("STRING")
    .help("Output file name. '-' means stdout");
  psr.add_option("-V").dest("verbose").metavar("BOOL").action("store_true")
    .help("Verbose mode");
  
  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();
  if (lurker::main(opt, args)) {
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}

