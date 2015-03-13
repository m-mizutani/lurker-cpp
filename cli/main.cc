/*
 * Copyright (c) 2014 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
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


#include <fstream>
#include "../src/lurker.h"
#include "./optparse.h"

int main(int argc, char *argv[]) {
  // Configure options
  optparse::OptionParser psr = optparse::OptionParser();
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");
  psr.add_option("-r").dest("pcap_file")
    .help("Specify pcap_file for dry run mode");
  /*
  psr.add_option("-f").dest("filter")
    .help("Filter");
  */

  psr.add_option("-a").dest("enable_arp").action("store_true")
    .help("Enable ARP spoofing");

  // Output options
  psr.add_option("-p").dest("zmq_pub").metavar("INT")
    .help("Port number to publish result as ZMQ");
  psr.add_option("-z").dest("zmq_push").metavar("STR")
    .help("Server name and port number to push result as ZMQ");
  psr.add_option("-o").dest("output").metavar("STRING")
    .help("Output file name. '-' means stdout");
  psr.add_option("-b").dest("blow").metavar("BOOL").action("store_true")
    .help("Enable blow mode");
  psr.add_option("-v").dest("verbose").metavar("BOOL").action("store_true")
    .help("Verbose mode");
  
  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();
  

  // Setup Lurker
  lurker::Lurker *lurker = nullptr;
  if (opt.is_set("interface")) {
    lurker = new lurker::Lurker(opt["interface"]);
  } else if (opt.is_set("pcap_file")) {
    lurker = new lurker::Lurker(opt["pcap_file"], true);  // enable dry run mode
  }

  if (lurker == nullptr) {
    std::cerr << "Should set interface with '-i' option" << std::endl;
    return EXIT_FAILURE;
  }

  if (args.size() == 0) {
    std::cerr << "No target is configured" << std::endl;
    return EXIT_FAILURE;
  }

  try {
    if (opt.is_set("filter")) {
      lurker->set_filter(opt["filter"]);
    }

    if (opt.get("enable_arp")) {
      lurker->enable_arp_spoof();
    }

    if (opt.get("verbose")) {
      // TODO: need to manage verbose mode.
    }

    for (size_t i = 0; i < args.size(); i++) {
      lurker->add_target(args[i]);
    }

    lurker->run();
  } catch (const lurker::Exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

