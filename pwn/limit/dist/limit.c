#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <malloc.h>

char* chunks[0x10] = {0};
uint16_t sizes[0x10] = {0};

int main() {
    uint64_t idx;
    uint64_t sz;
    char* limit;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    free(malloc(0x418));
    limit = (char*) sbrk(0);
    puts("hi");
    while (1) {
        puts("Options:");
        puts("1) malloc up to 0x100 bytes");
        puts("2) free chunks and clear ptr");
        puts("3) print chunks using puts");
        puts("4) read to chunks with max possible size");
        printf("> ");
        uint option;
        if (!scanf("%d", &option)) {
            getchar();
        }
        switch (option) {
            case 1:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                printf("Size: ");
                if (!scanf("%ld", &sz) || !sz || sz > 0xf8) {
                    puts("0 < sz <= 0xf8");
                    break;
                }
                chunks[idx] = malloc(sz);
                if (chunks[idx] > limit) {
                    puts("hey where do you think ur going");
                    // if (malloc_usable_size(chunks[idx])) free(chunks[idx])
                    chunks[idx] = 0;
                    break;
                }
                uint16_t usable_size = sz > 0x18 ? (sz+7&~0xf)+8 : 0x18;
                sizes[idx] = usable_size;
                break;
            case 2:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (chunks[idx] == 0) {
                    puts("no chunk at this idx");
                    break;
                }

                free(chunks[idx]);
                chunks[idx] = 0;
                sizes[idx] = 0;
                break;
            case 3:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (!chunks[idx]) {
                    puts("no chunk at this idx");
                    break;
                }
                printf("Data: ");
                puts(chunks[idx]);
                break;
            case 4:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (!chunks[idx]) {
                    puts("no chunk at this idx");
                    break;
                }
                printf("Data: ");
                int len = read(0, chunks[idx], (uint) sizes[idx]);
                if (len <= 0) {
                    puts("read failed");
                    break;
                }
                chunks[idx][len] = 0;
                break;
            default:
                puts("invalid option");
                break;
        }
        puts("");
    }
    _exit(0);
}
