#include <stdio.h>
#include <stdint.h>
#include <string.h>

int check_flag_1(const char *flag);
int check_flag_2(const char *flag);

void check(const char *flag_inner) {
    char inp[256];
    *((uint64_t *) inp) = 0xfedcba9876543210ULL;

    memcpy(inp + 8, flag_inner, 16);
    if (check_flag_1(inp)) {
        puts("incorrect password");
        return;
    }
    puts("hmmm, interesting");

    memcpy(inp + 8 + 16, flag_inner + 16, 38);
    if (check_flag_2(inp)) {
        puts("incorrect password");
        return;
    }
    puts("successfully logged in");
    puts("welcome back, Robert'); DROP TABLE Students;-- ");
}

int main() {
    puts("login");

    char username[256] = {0};
    printf("username: ");
    scanf("%255s", username);

    char password[256] = {0};
    printf("password: ");
    scanf("%255s", password);

    if (strcmp(username, "bobby_tables")) {
        puts("a user by that name does not exist");
        return 0;
    }

    if (strlen(password) != 61 || strncmp(password, ".;,;.{", 6) || password[60] != '}') {
        puts("incorrect password");
        return 0;
    }

    check(password + 6);
}
