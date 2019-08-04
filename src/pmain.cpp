#include <iostream>
#include <libnet.h>

#include "pnetworkservice.h"
#include "util/pstring.h"


#define MAX_STRING 512

using namespace pnetwork;

static const char* str_send_arp = "send_arp";
static const char* str_exit = "exit";

void printMenu();
int process(char* input);

int main()
{
    char input[MAX_STRING];

    printMenu();

    do {
        std::cin.getline(input, MAX_STRING-1);
    } while(!process(input));


    PNetworkService::destroy();

    return 0;
}


void printMenu() {
    puts("Usage:send_arp <interface> <sender ip> <target_ip>");
}

int process(char* input) {

    char** list = nullptr;
    unsigned int size = pstring::strtok(input, list);

    if(strcmp(str_send_arp, list[0]) == 0) {
        PNetworkService::getInstance()->spoofARP(list[1], list[2], list[3]);
    } else if(strcmp(str_exit, list[0]) == 0) {
        pstring::freeList(list, size);
        return 1;
    } else {
        printf("Invalid Operation!\n");
    }

    pstring::freeList(list, size);

    return 0;
}


