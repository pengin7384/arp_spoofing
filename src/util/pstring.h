#pragma once
#include <malloc.h>

namespace pstring {

const int MAX_STRING = 512;

/**
* @brief freeList
* @details Free list memory
* @param list Target pointer to free
* @param size Target pointer size
*/
void freeList(char** list, unsigned int size) {
    for(unsigned int i=0; i<size; i++) {
        free(list[i]);
    }
    free(list);
    list = nullptr;
}

/**
* @brief getSize
* @details Get Size of string("Hello World!":2)
* @param str Target string
* @return Value of size
*/
unsigned int getSize(char* str) {
    unsigned int cnt = 1, index = 0;
    while(str[index]) {
        if(str[index] == ' ') {
            cnt++;
        }
        index++;
    }
    return cnt;
}

/**
* @brief strcpy
* @details Copy string
* @param src_str Source string
* @param dest_str Destination string
* @param len Length of string
*/
void strcpy(char* src_str, char* dest_str, unsigned int len) {
    for(unsigned int i=0; i<len; i++) {
        dest_str[i] = src_str[i];
    }
}

/**
* @brief strtok
* @details Change string to string list
* @param str Source string
* @param list Destination string list
* @return Size of list(0:fail)
*/
unsigned int strtok(char* str, char** &list) {
    unsigned int size = getSize(str);
    list = reinterpret_cast<char**>(malloc(sizeof(char*)*size));
    if(list == nullptr) { // Fail to malloc

        return 0;
    }

    char temp[MAX_STRING];
    unsigned int index = 0, temp_index = 0, list_index = 0;

    do {
        if(str[index] == ' ' || str[index] == '\0') {
            temp[temp_index++] = '\0';
            list[list_index] = reinterpret_cast<char*>(malloc(sizeof(char)*temp_index));


            if(list[list_index] == nullptr) { // Fail to malloc
                freeList(list, list_index);
                return 0;
            }

            strcpy(temp, list[list_index++], temp_index);
            temp_index = 0;
        } else {
            temp[temp_index++] = str[index];
        }
    } while(str[index++]);

    return size;
}

}
