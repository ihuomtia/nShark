#include "layers.hpp"

#include "protocols/tcp.hpp"
#include "protocols/ip.hpp"
#include "protocols/psdhdr.hpp"
#include "utils.hpp"
#include "options.hpp"

#include <stdio.h>
#include <arpa/inet.h>
#include <string>
#include <string.h>
#include <iostream>
#include <arpa/inet.h>
#include <time.h>


/* IP Packet */
IP::IP(){
    repr[0] = 'I';

    // default values
    fields.version = 4L;
    fields.ihl = 5L;
    fields.tos = 0x0;
    fields.total_length = htons(40);
    fields.id = htons(1);
    fields.frag_off = 0L;
    fields.ttl = 64;
    fields.protocol = 6;
    fields.checksum = 0x0;
    this->setdstaddr("127.0.0.1");
    this->setsrcaddr("127.0.0.1");
}

size_t IP::compile(){

    if (CLEAN_BEFORE_COMPILE)
        this->clear();

    int len;

    unsigned int short chksum;

    /* Checksum */
    chksum = utils::checksum((unsigned short *) &fields, sizeof(fields));
    fields.checksum = chksum;
    /* Append to payload */
    len = append((uint8_t *) &fields, sizeof(fields));

    compiled = true;
    return len;
}

size_t IP::frompayload(char *data){
    size_t s;

    for (s = 0; s <= sizeof(ip_t); s++)
         ( (char *) &fields)[s] = data[s];

    return s;
}

void IP::setdstaddr(const char *addr){
    this->fields.dst = inet_addr(addr);
}

void IP::setsrcaddr(const char *addr){
    this->fields.src = inet_addr(addr);
}


Packet IP::operator /(IP pkt){
    static Packet new_pkt;
    //new_pkt.clear();
    new_pkt.append((uint8_t *) &this->fields, sizeof(this->fields));
    new_pkt.append((uint8_t *) &pkt.fields, sizeof(pkt.fields));

    return new_pkt;
}

Packet IP::operator /(Packet pkt){
    static Packet new_pkt;
    //new_pkt.clear();
    new_pkt.append((uint8_t *) &this->fields, sizeof(this->fields));
    new_pkt.append((uint8_t *) &pkt.fields, pkt.length());

    return new_pkt;
}


Packet IP::operator /(TCP pkt){
    static Packet new_pkt;

    new_pkt.clear();

   // pkt.compile();
    //this->compile();

    // Calculating tcp checksum

    uint16_t sum = utils::tcp_checksum((ip_t *) &this->fields, (tcp_t *) &pkt.fields);
    pkt.fields.checksum = sum;

    pkt.compile();  // Recompile tcp packet to add checksum
    this->compile();

    new_pkt.append((uint8_t *) this->raw_payload(), this->length()); // Adding ip header to the top of the new pkt
    new_pkt.append((uint8_t *) pkt.raw_payload(), pkt.length()); // Adding tcp header to the pkt

    return new_pkt;
}


void IP::summarize(){
    using namespace std;
    struct in_addr in;
    cout << "[IP Packet: " << fields.ihl*4 << " bytes ]" << endl;
    in.s_addr = fields.src;
    cout << "\tSource Addr: " << inet_ntoa(in) << endl;
    in.s_addr = fields.dst;
    cout << "\tDest Addr: " << inet_ntoa(in) << endl;
    cout << "\tChecksum:  " << ntohs(fields.checksum) << endl;
    cout << "\tProtocol: "  << fields.protocol << " ( " << (fields.protocol == TCP_PROTO_NUM ? "TCP": "N/A") << " )" << endl;
    cout << "\tTOS:      "  << fields.tos << endl;
}
/* TCP Packet */
TCP::TCP(){

    if(TCP_RAND_SPORT){
        srand(time(NULL));
        fields.sport = htons(rand() % 1024) ;}
    else
        fields.sport = htons(DEFAULT_TCP_SPORT);
    fields.dport   = htons(80);
    if (TCP_RAND_SEQ){
        srand(time(NULL));
        fields.seq = htonl(rand() % 31337);}
    else
        fields.seq = htonl(DEFAULT_TCP_SEQ);
    fields.ack_seq    = 0x0;
    fields.res1 = 0x0;
    fields.res2 = 0x0;
    fields.dataofs = 5L;

    fields.fin = fields.syn = fields.rst = fields.psh = fields.ack = fields.urg = 0;
    toggleflag('S');

    fields.window  = htons(8192);
    fields.checksum= 0x0;
    fields.urg_ptr = 0x0;
}

size_t TCP::compile(){
    unsigned int len;
    if(CLEAN_BEFORE_COMPILE)
        this->clear();

    len = append((uint8_t*) &fields, fields.dataofs * 4);

    while (len % 4 != 0)
        len = append((uint8_t *) "\x00", 1);

    compiled = true;
    return len;
}

void TCP::toggleflag(char flg){
    switch(flg){
        case 'S':
            this->fields.syn = this->fields.syn ^ 1;
        break;
        case 'F':
            this->fields.fin = this->fields.syn ^ 1;
        break;
        case 'R':
            this->fields.rst = this->fields.syn ^ 1;
        break;
        case 'P':
            this->fields.psh = this->fields.syn ^ 1;
        break;
        case 'U':
            this->fields.urg = this->fields.syn ^ 1;
        break;
        case 'A':
            this->fields.ack = this->fields.syn ^ 1;
        break;
    }
}

size_t TCP::frompayload(void *data, size_t l){
    size_t s;
    for (s = 0; s < l; s++)
        ((char *) &fields)[s] = ((char *) data)[s];
    return s;
}

Packet TCP::operator /(Packet pkt){
    static Packet new_pkt;
    new_pkt.clear();

    if (COMPILE_PACKET_LAYERING)
        this->compile();


    new_pkt.append((uint8_t *) this->raw_payload(), sizeof(this->fields));
    new_pkt.append((uint8_t *) pkt.raw_payload(), pkt.length());

    return new_pkt;
}

Packet TCP::operator /(const char *pkt){
    static Packet new_pkt;
    new_pkt.clear();

    if(COMPILE_PACKET_LAYERING)
        this->compile();

    new_pkt.append((uint8_t *) &this->fields, sizeof(this->fields));
    new_pkt.append((uint8_t *) pkt, strlen(pkt));

    return new_pkt;
}

void TCP::setsport(uint16_t port){
    fields.sport = htons(port);
}

void TCP::setdport(uint16_t port){
    fields.dport = htons(port);
}


void TCP::summarize(){
    using namespace std;
    cout << "[TCP Packet: " << fields.dataofs * 4 << " Bytes]" << endl;
    cout << "\tSrc Port:  " << ntohs(fields.sport) << endl;
    cout << "\tDst Port:  " << ntohs(fields.dport) << endl;
    cout << "\tChecksum:  " << ntohs(fields.checksum) << endl;
    cout << "\tWindow:    " << ntohs(fields.window) << endl;
    cout << "\tFlags:  "
         << (fields.fin ? " FIN":"")
         << (fields.syn ? " SYN":"")
         << (fields.rst ? " RST":"")
         << (fields.psh ? " PSH":"")
         << (fields.ack ? " ACK":"")
         << (fields.urg ? " URG":"") << endl;
}

void TCP::clearflags(){
    fields.syn = fields.rst = fields.ack = fields.psh = fields.fin = 0x0;
}

/* END TCP Packet */

/* Ether */
Ether::Ether() {
    this->clear();
    for (int i = 0; i < 6; i++)
        fields.dst[i] = fields.src[i] = 0x0;
    fields.type = 0x0;
}

size_t Ether::compile(){
    return this->append((uint8_t *) &fields, sizeof(fields) );
}
