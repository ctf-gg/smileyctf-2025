#include "asm/pgtable.h"
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/pagewalk.h>
#include <linux/printk.h>
#include <linux/uaccess.h>

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

struct page *pages[512];

static long coproc_verify(long uaddr, long size) {
  if ((uaddr & 0xfff) != 0)
    return 1;
  size = (size + 0xfff) & ~0xfff;
  if (size == 0)
    return 1;

  long npages = size >> 12;
  if (npages > 512)
    return 1;

  long pages_done = get_user_pages_unlocked(uaddr, npages,
                                            (struct page **)&pages, FOLL_WRITE);

  if (pages_done <= 0 || (pages_done != npages)) {
    return 1;
  }

  return 0;
}

typedef struct {
  unsigned long vaddr;
  unsigned long paddr;
} CoprocWalk;

static int coproc_pte_entry(pte_t *pte, unsigned long addr, unsigned long next,
                            struct mm_walk *walk) {
  CoprocWalk *ctx = (CoprocWalk *)walk->private;
  if (addr == ctx->vaddr) {
    ctx->paddr = pte_pfn(ptep_get(pte));
    return 1;
  }
  return 0;
}

struct mm_walk_ops coproc_walk_ops = {.pte_entry = coproc_pte_entry};

static long coproc_virt_to_phys(long uaddr) {
  CoprocWalk ctx = {.vaddr = uaddr, .paddr = 0};
  mmap_read_lock(current->mm);
  walk_page_range(current->mm, 0, 0x100000000, &coproc_walk_ops, (void *)&ctx);
  mmap_read_unlock(current->mm);
  return ctx.paddr << 12;
}

static void coproc_configure(unsigned long paddr) {
  asm volatile(".intel_syntax noprefix\n"
               "mov rax, %[paddr]\n"
               "mov dx, 0x501\n"
               "in al, dx\n"
               ".att_syntax prefix\n"
               :
               : [paddr] "r"(paddr)
               : "rax", "rdx", "memory");
}

static void coproc_process(void) {
  asm volatile(".intel_syntax noprefix\n"
               "xor eax, eax\n"
               "mov dx, 0x501\n"
               "in al, dx\n"
               ".att_syntax prefix\n" ::
                   : "rax", "rdx", "memory");
}

static long coproc_ioctl(struct file *file, unsigned int cmd,
                         unsigned long user_request) {
  Config config;
  if (copy_from_user(&config, (const void *)user_request, sizeof(Config))) {
    return -EINVAL;
  }

  if (config.packets.len > 128 || config.height > 128 || config.width > 128 ||
      config.height < 3 || config.width < 3) {
    return -EINVAL;
  }

  if (coproc_verify(user_request, 1)) {
    printk("failed to verify config\n");
    return -EINVAL;
  }
  if (coproc_verify(config.packets.base, config.packets.len * sizeof(Packet))) {
    printk("failed to verify packets\n");
    return -EINVAL;
  }
  if (coproc_verify(config.input,
                    config.width * config.height * sizeof(Pixel))) {
    printk("failed to verify input\n");
    return -EINVAL;
  }
  if (coproc_verify(config.output,
                    config.width * config.height * sizeof(Pixel))) {
    printk("failed to verify output\n");
    return -EINVAL;
  }

  u32 paddr;
  Config *c = (Config *)user_request;
  paddr = coproc_virt_to_phys(config.input) | (1 << 31);
  if (copy_to_user((void *)&c->input, &paddr, 4))
    return -EINVAL;
  paddr = coproc_virt_to_phys(config.output) | (1 << 31);
  if (copy_to_user((void *)&c->output, &paddr, 4))
    return -EINVAL;
  paddr = coproc_virt_to_phys(config.packets.base) | (1 << 31);
  if (copy_to_user((void *)&c->packets.base, &paddr, 4))
    return -EINVAL;

  coproc_configure(coproc_virt_to_phys(user_request) | (1 << 31));
  coproc_process();
  return 0;
}

static struct file_operations coproc_fops = {
    .unlocked_ioctl = coproc_ioctl,
};

static struct miscdevice coproc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "coproc",
    .fops = &coproc_fops,
};

static int coproc_init(void) {
  if (misc_register(&coproc_device) < 0) {
    printk(KERN_ALERT "[-] failed to initialize device\n");
    return -1;
  }
  return 0;
}

static void coproc_cleanup(void) {}

module_init(coproc_init);
module_exit(coproc_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("unvariant");
