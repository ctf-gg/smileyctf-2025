// clang-format off
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "VCPU.h"
#include "verilated.h"
#include "VCPU___024root.h"
// clang-format on

#define REGS (tb->rootp->CPU__DOT__regs_i__DOT__registers.m_storage)
#define MEM (tb->rootp->CPU__DOT__ram_i__DOT__ram)
#define WDATA (tb->rootp->CPU__DOT__mem_signals.__PVT__wdata)

VCPU *tb;

char *mem(unsigned int offset) {
  if (offset >= MEM.size() * 4) {
    printf("invalid pointer!\n");
    exit(0);
  }
  return &((char *)(MEM.m_storage))[offset];
}

int main(int argc, char **argv) {
  Verilated::commandArgs(argc, argv);

  tb = new VCPU;
  tb->o_hypervisor_call = 0;

  tb->i_rst = 1;
  tb->eval();
  tb->i_rst = 0;
  tb->eval();

  int cont = 0;

  // Tick the clock until we are done
  while (!Verilated::gotFinish()) {
    tb->i_clk = 1;
    tb->eval();
    tb->i_clk = 0;
    tb->eval();

    if (tb->o_hypervisor_call) {
      int sysno = REGS[10];
      unsigned int *args = &REGS[11];

      int ret = -1;
      switch (sysno) {
      case 0: {
        ret = read(0, mem(args[0]), args[1]);
        break;
      }
      case 1: {
        ret = write(1, mem(args[0]), args[1]);
        break;
      }
      }

      WDATA = ret;
      tb->o_hypervisor_call = 0;
    }
  }

  printf("done executing\n");
  printf("exit code: %d\n", REGS[10]);
  return 0;
}