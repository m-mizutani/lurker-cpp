Lurker
============================================

Overview
--------------------------------------------
Lurker disguises TCP listen port and collecting payload data that attacker sent.


Install
--------------------------------------------

### Requires
- libpcap
- libswarm (install from [github](https://github.com/m-mizutani/swarm))

### Setup

    % git clone https://github.com/m-mizutani/swarm.git
    % cd swarm
    % cmake . && make
    % cd ..
    % git clone https://github.com/m-mizutani/lurker.git
    % cd lurker
    % cmake -DINC_DIR=../swarm/src -DLIB_DIR=../swarm/lib .
    % make
    % sudo make install

Usage
--------------------------------------------

Sample command line

    % lurker -i eth0 -f "port not 22"
