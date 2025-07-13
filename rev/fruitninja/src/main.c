typedef unsigned int uint;
#define FLAG_LEN 37
#define B64_LEN 50
#define BASE 64

int read(char *buf, int n);
void write(char *buf, int n);

uint fruits[][1] = {{1}};

int main() {
    unsigned char buf[FLAG_LEN + 1];
    
    write("cut my fruit in half: ", 22);
    if (read(buf, FLAG_LEN) != FLAG_LEN) {
        write("no\n", 3);
        return 1;
    }
    buf[FLAG_LEN] = '\0';
    
    uint idxs[B64_LEN];
    uint j = 0;
    uint previous = 0;
    for (uint i = 0; i <= FLAG_LEN; i++) {
        // 6 4 2
        //  2 4 6
        uint c = buf[i];
        uint bits_to_take = 6 - (i % 3) * 2;
        uint bits_left = 8 - bits_to_take;

        idxs[j++] = ((c & ((1 << bits_to_take) - 1)) << (6 - bits_to_take)) | previous;
        if (bits_left == 6) {
            // 6 bits left in the current byte
            idxs[j++] = (c >> bits_to_take);
            previous = 0;
        }
        else {
            // store bits left in previous
            previous = (c >> bits_to_take);
        }
    }

    // for (uint i = 0; i < B64_LEN; i++) {
    //     printf("%u ", idxs[i]);
    // }
    // printf("\n");

    uint win = B64_LEN;
    for (uint i = 0; i < B64_LEN; i++) {
        uint s = 0;
        uint idx = idxs[i];
        for (uint j = 0; j < BASE; j++) {
            if (j >= idx) {
                s -= fruits[i][j];
            } else {
                s += fruits[i][j];
            }
        }
        
        if (s == 0){
            --win;
        }
    }

    if (win == 0) {
        write("yes\n", 4);
    } else {
        write("no\n", 3);
    }
}

// tmp
void write(char *buf, int n) {
    for (int i = 0; i < n; i++) {
        putchar(buf[i]);
    }
}

int read(char *buf, int n) {
    for (int i = 0; i < n; i++) {
        buf[i] = getchar();
    }
    return n; 
}