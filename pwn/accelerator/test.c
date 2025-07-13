#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

typedef uint32_t u32;
typedef uint8_t u8;

typedef struct {
  u32 width;
  u32 height;
  struct {
    u32 base;
    u32 len;
  } packets;
  u32 input;
  u32 output;
} Config;

typedef struct {
  u32 kind;
  struct {
    u32 x;
    u32 y;
    u32 width;
    u32 height;
  } bounds;
} Packet;

typedef struct {
  u8 r;
  u8 g;
  u8 b;
  u8 a;
} Pixel;

int main() {
  Config *config;
  int fd;

  fd = open("/dev/coproc", O_RDWR);
  config = (Config *)mmap(NULL, 0x1000, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE,
                          -1, 0);
  printf("addr = %p\n", config);
  assert(ioctl(fd, 0, config) == -1);
  perror("ioctl");
  assert(errno == EINVAL);

  // int tmp = open("/sbin/modprobe", O_RDONLY);
  // config = (Config *)mmap(NULL, 0x1000, PROT_READ,
  //                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, tmp, 0);
  // assert(ioctl(fd, 0, config) == -1);
  // perror("ioctl");
  // assert(errno == EINVAL);

  config = (Config *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
  printf("config = %p\n", config);
  assert(ioctl(fd, 0, config) == -1);
  perror("ioctl");
  assert(errno == EINVAL);

  char *input = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
  char *output = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
  Packet *packets =
      (Packet *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);

  packets[0].kind = 3;
  packets[0].bounds.x = 0;
  packets[0].bounds.y = 0;
  packets[0].bounds.width = 5;
  packets[0].bounds.height = 5;

  config->height = 100;
  config->width = 100;
  config->input = (u32)input;
  config->output = (u32)output;
  config->packets.base = (u32)packets;
  config->packets.len = 1;
  assert(ioctl(fd, 0, config) == -1);
  perror("ioctl");
  assert(errno == EINVAL);

  for (int i = 3; i <= 5; i++) {
    memset(input, 0x41, 0x100);

    packets[0].kind = i;
    packets[0].bounds.x = 0;
    packets[0].bounds.y = 0;
    packets[0].bounds.width = 5;
    packets[0].bounds.height = 5;

    config->height = 5;
    config->width = 5;
    config->input = (u32)input;
    config->output = (u32)output;
    config->packets.base = (u32)packets;
    config->packets.len = 1;
    ioctl(fd, 0, config);

    printf("input = %s\n", input);
    printf("output = %s\n", output);
  }

  printf("done\n");
}