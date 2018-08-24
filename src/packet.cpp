#include "packet.hpp"

#include "utils.hpp"
#include "options.hpp"
#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"

#include <stdlib.h>
#include <iostream>
#include <stdint.h>
#include <string.h>


Packet::Packet(){
    this->clear();
    compiled = false;
}

void Packet::setlength(size_t s){
    this->size = s;
}

size_t Packet::hexdump(){
    return utils::hexdump((char *) this->payload, this->size);
}

size_t Packet::length(){
    return this->size; /* Returns the packet length */
}

uint8_t *Packet::raw_payload(){
    return this->payload; /* Returns a pointer to the bigginig of the packets payload */
}

size_t Packet::append(uint8_t *data, size_t n){
    u_int i, curr_size;
    curr_size = this->size;
    for (i = this->size; i < (n + curr_size); i++){
        this->payload[i] = data[(i - curr_size)];
        this->size += sizeof(this->payload[i]);
    }
    return i;
}

void Packet::clear(){
    this->size = 0;
    this->compiled = false;
    //memset((void *) this->payload, '\0', MAX_PAYLOAD_SIZE);
}


void Packet::operator =(Packet pkt){
    this->size = pkt.length();
    using namespace std;
    memcpy(this->payload, pkt.raw_payload(), pkt.length());
}

Packet::~Packet(){
    /* Clear the memory after destroying the packet */
    this->clear();
}

void Packet::present(){
    for (int i = 0; this->repr[i] != '\0'; i++){
        switch(this->repr[i]){
            case 'T':
                std::cout << "TCP/ ";
            break;
            case 'I':
                std::cout << "IP/ ";
            break;
        }
    }
    std::cout << std::endl;
}
