#include <iostream>
#include "src/network/network_service.h"
#include "util.h"

int main(int argc, char *argv[])
{
    if (argc % 2 != 0) {
        printUsage();
        return 1;
    }

    char **sd_list, **tg_list;
    int cnt = splitArg(argc, argv, sd_list, tg_list);

    spoof::NetworkService::getInstance()->spoofArp(argv[1], cnt, sd_list, tg_list);

    free(sd_list);
    free(tg_list);

    return 0;
}


