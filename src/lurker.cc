#include <swarm.h>



int main() {
  swarm::CapPcapDev dev("en1");
  swarm::NetDec nd;
  dev.bind_netdec(&nd);
  dev.start();
}
