#include "util.h"

void printUsage()
{
    puts("./arp_spoof <interface> <sender_ip> <target_ip");
}

int splitArg(int argc, char **argv, char **&sd_list, char **&tg_list)
{
    int cnt = argc / 2 - 1;
    sd_list = reinterpret_cast<char**>(malloc(sizeof(cnt)));
    tg_list = reinterpret_cast<char**>(malloc(sizeof(cnt)));

    for (int i = 0; i < cnt; i++) {
        sd_list[i] = argv[2 * i + 2];
        tg_list[i] = argv[2 * i + 3];
    }
    return cnt;
}
