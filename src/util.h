#pragma once
#include <malloc.h>

void printUsage();
int splitArg(int argc, char **argv, char **&sd_list, char **&tg_list);
