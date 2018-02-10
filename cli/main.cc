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
#include "../src/lurker.hpp"
#include "./optparse.h"

int main(int argc, char *argv[]) {
  // Configure options
  optparse::OptionParser psr = optparse::OptionParser();
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");
  psr.add_option("-r").dest("pcap_file")
    .help("Specify pcap_file for dry run mode");

  // Output options
  psr.add_option("-f").dest("fluentd").metavar("STR")
    .help("Fluentd inet destination (e.g. 10.0.0.1:24224)");
  psr.add_option("-o").dest("output").metavar("STRING")
    .help("Output file path. '-' means stdout");
  psr.add_option("-t").dest("target").metavar("STRING")
    .help("File path of target list");
  psr.add_option("-H").dest("hexdata").action("store_true")
    .help("Enable hex format data log instead of binary data");
  
  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();
  

  // Setup Lurker
  lurker::Lurker *lurker = nullptr;
  if (opt.is_set("interface")) {
    lurker = new lurker::Device(opt["interface"]);
  } else if (opt.is_set("pcap_file")) {
    lurker = new lurker::DryRun(opt["pcap_file"]);    
  } else {
    std::cerr << "Must set '-i' or '-r' option" << std::endl;
    return EXIT_FAILURE;
  }

  try {
    // Set target
    if (opt.is_set("target")) {
      lurker->import_target(opt["target"]);
    }
    for (size_t i = 0; i < args.size(); i++) {
      lurker->add_target(args[i]);
    }

    if (!lurker->has_target()) {
      std::cerr << "Warning: No target is configured" << std::endl;
    }
    
    // Configure output
    if (opt.is_set("fluentd")) {
      lurker->output_to_fluentd(opt["fluentd"]);
    }
    if (opt.is_set("output")) {
      lurker->output_to_file(opt["output"]);
    }

    /*    
    if (opt.get("hexdata")) {
      lurker->enable_hexdata_log();
    } else {
      lurker->disable_hexdata_log();
    }
    */
    
    // Start
    lurker->run();
  } catch (const lurker::Exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  delete lurker;
  return EXIT_SUCCESS;
}

