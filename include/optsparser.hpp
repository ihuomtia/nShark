#ifndef OPTSPARSER_HPP
#define OPTSPARSER_HPP

#include "output.hpp"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <ctype.h>

using namespace std;

bool isin(char buffer[], char c){ /* Like in python, if 'c' in 'you know how to c, then you better see' */
    for (int x = 0; buffer[x] != '\0'; x++){
        if (buffer[x] == c) return true;
        else continue;
    }

    return false;
}

uint how_much_in(char buffer[], char c){
    uint count = 0;
    for (int x = 0; buffer[x] != '\0'; x++){
        if (buffer[x] == c) count+=1;
    }
    return count;
}

int parse_port(char buf[], vector<uint16_t> *ports){
    if (isin(buf, ',')){
        int i, j;
        for (i = j = 0; buf[i] != '\0'; i++){
            if (buf[i] == ','){
                char *c_port = new char[255];
                memset(c_port, 0x0, 255); 
                strncpy(c_port, buf+j, i - j);

                j = ++i;
                if (isin(c_port, '-')){
                    /* If a port range specified */
                    /* TODO */
                }

                /* Adding port to the ports */
                else ports->push_back(atoi(c_port));
            }
            else {
                continue;
            }
        }
        /* Because always the last one in buf doesn't added to the hosts */
        char *c_port = new char[255];
        memset(c_port, 0x0, 255);
        strncpy(c_port, buf+j, i - j);
        if (!(isin(c_port, '-'))) ports->push_back(atoi(c_port));
    }
    else {
        if (!(isin(buf, '-')))
                ports->push_back(atoi(buf));
        else if (buf[0] == '-') {
            for (int i = 1; i < 65535; i++) {
                ports->push_back(i);
            }
        }
        else {
            // TODO: fix this miss
            /* I know this block is a bit confusing and it's not so clean, but it does the work :) */
            char temp1[255];
            char temp2[255];
            memset(temp1, 0x0, 255);
            memset(temp2, 0x0, 255);
            strcpy(temp1, buf);
            strcpy(temp2, buf);
            char *minus = index(temp1, '-');
            temp2[(strlen(buf) - (strlen(minus+1))) - 1] = '\0'; /* to get the first digit */
            strcpy(temp1, minus+1);

            int digit1 = atoi(temp2); /* Confusing right :p */
            int digit2 = atoi(temp1);

            for (int i = digit1; i <= digit2; i++) {
                ports->push_back(i);
            }

        }
    }

    return 0;
}

int parse_host(char buf[], vector<char *> *hosts){
    if (isin(buf, ',')){
        int i, j;
        for (i = j = 0; buf[i] != '\0'; i++){
            if (buf[i] == ','){
                char *host = new char[255];
                memset(host, 0x0, 255);
                strncpy(host, buf+j, i - j);

                j = ++i;
                if (isin(host, '-')){
                    /* TODO: If a host range specified  */
                }
                if (isin(host, '/')){
                    /*  */
                    /* TODO: If a cidr format specified */
                }
                /* Adding host to the hosts */
                if (!(isin(host, '/') || isin(host, '-'))) hosts->push_back(host);
            }
            else {
                continue;
            }
        }
        /* Because always the last one in buf doesn't added to the hosts */
        char *host = new char[255];
        memset(host, 0x0, 255);
        strncpy(host, buf+j, i - j);
        if (!(isin(host, '/') || isin(host, '-'))) hosts->push_back(host);
    }
    else {
        if (!(isin(buf, '/') || isin(buf, '-'))) hosts->push_back(buf);
    }

    return 0;
}

bool check_host(char buf[]){
    return 1;
}

bool check_port(uint16_t port){
    if (port < 0 || port > 65535)
        return false;
    else
        return true;
}

int add_top_100_ports(vector<uint16_t> ports){
    ports.push_back(80);
    return 1;
}

/*
void pa_port(char buf[]){
        int index = 0, old_index = 0;
        char port[12];
        int i = 0;
        for (uint x = 0; x <=  how_much_in(buf, ','); x++){
            if (x != how_much_in(buf, ',')) for (; buf[index] != ','; index++);
            else for (; buf[index] != '\0'; index++);
            strncpy(port, buf+old_index+i, index - old_index);
            port[index-old_index-1] = '\0';

            printf("%d\n", atoi(port));

            old_index = index;
            i = 1;
            index += 1;
        }
}
*/
#endif // OPTSPARSER_HPP
