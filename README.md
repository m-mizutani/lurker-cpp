Lurker
============================================

Overview
--------------------------------------------
Lurker disguises TCP listen port and collecting payload data that attacker sent.


Install
--------------------------------------------

### Requires

- libpcap
- libev
- libfluent (install from [github]
- libswarm (install from [github](https://github.com/m-mizutani/libfluent))

### Setup

    % git clone https://github.com/m-mizutani/lurker.git
    % cd lurker
    % cmake .
    % make
    % sudo make install

If you need to specify libfluent prefix, you can use `-DWITH_FLUENT` option.

    % git clone https://github.com/m-mizutani/lurker.git
    % cd lurker
    % cmake -DWITH_FLUENT=$HOME/local .
    % make
    % sudo make install
    
Usage
--------------------------------------------

Monitor eth0 and reply for a packet to 10.0.0.200 and TCP port 3128. Output log data to `lurker.log` as msgpack format.

    % lurker -i eth0 10.0.0.200:3128 -o lurker.log

Monitor eth0 and reply for all packet to 10.0.0.200 (any TCP port). Output to fluentd for localhost, port 24224.

    % lurker -i eth0 "10.0.0.200:*" -f localhost:24224

The output message for fluentd contains binary data. If you want to save it DB that doesn't support binary format such as MongoDB, you can add `-H` option to convert HEX string from binary data.

    % lurker -i eth0 "10.0.0.200:*" -f localhost:24224 -H

Dry run mode, read packet from `test.pcap`. Just extract TCP first data segment.

    % lurker -r test.pcap

