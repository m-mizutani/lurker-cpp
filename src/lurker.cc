#include <swarm.h>



int main(int argc, char *argv[]) {
  swarm::CapPcapDev dev(argv[1]);
  swarm::NetDec nd;
  dev.bind_netdec(&nd);
  dev.start();
}
