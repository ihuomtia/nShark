#include "scanners.hpp"

#include "rocket.hpp"
#include "options.hpp"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>


TCPScanner::TCPScanner(){
    if (!TCP_RAND_SPORT)
        sport = DEFAULT_TCP_SPORT;
#ifdef SPORT_INCREASE
    inc_counter = 0;
#endif
}

TCPScanner::~TCPScanner(){
    return;
}


bool TCPScanner::scan_syn(const char *host, uint16_t port){
    tcp.setdport(port); /* Destination Port */
    ip.setdstaddr(host); /* Dest Addr */
    tcp.clearflags(); // Disable all flags

    tcp.toggleflag('S'); // Enable syn flag

    rocket.send(ip/tcp); /* Sending the packet */

    if (TCP_RAND_SPORT)
        sport = ntohs(tcp.fields.sport);

#ifdef SPORT_INCREASE
    if (inc_counter++ >= SPORT_INCREASE_EVERY){
        sport += SPORT_INCREASE_BY;
        tcp.setsport(sport);
        inc_counter = 0;
    }
#endif

    while (1){
        rocket.read(buffer, 1024);
        r_ip = rocket.decode_ip(buffer);
        if (r_ip.fields.dst == ip.fields.src) {
            r_tcp = rocket.decode_tcp(buffer + r_ip.length());
            if (r_tcp.fields.sport == tcp.fields.dport && r_tcp.fields.syn && r_tcp.fields.ack){
                return true;
            }
            else if (r_tcp.fields.sport == tcp.fields.dport && r_tcp.fields.rst && r_tcp.fields.ack){
                return false;
            }
        }
    }
}

bool TCPScanner::scan_fin(const char *host, uint16_t port){
    tcp.setdport(port); /* Destination Port */
    ip.setdstaddr(host); /* Dest Addr */

    tcp.clearflags(); /* Disable all flags */
    tcp.toggleflag('F'); /* Enable fin flag */

    if (TCP_RAND_SPORT)
        sport = ntohs(tcp.fields.sport);

#ifdef SPORT_INCREASE
    if (inc_counter++ >= SPORT_INCREASE_EVERY){
        sport += SPORT_INCREASE_BY;
        tcp.setsport(sport);
        inc_counter = 0;
    }
#endif


    rocket.send(ip/tcp); /* Sending the packet */
    int tries = 0;

    while (tries <= 3){
        rocket.read(buffer, 1024);
        r_ip = rocket.decode_ip(buffer);

        if (r_ip.fields.dst == ip.fields.src) {
            r_tcp = rocket.decode_tcp(buffer + r_ip.length());
            if (r_tcp.fields.sport == tcp.fields.dport){
                if (r_tcp.fields.rst){
                    return false;
                }
                else if (tries >= 3){
                    return true;
                }
            }
            tries++;
        }
    }
    return true;
}


bool TCPScanner::scan_xms(const char *host, uint16_t port){
    tcp.setdport(port); /* Destination Port */
    ip.setdstaddr(host); /* Dest Addr */

    tcp.clearflags(); /* Disable all flags */
    tcp.toggleflag('F'); /* Enable fin flag */
    tcp.toggleflag('U'); /* Enable urg flag */
    tcp.toggleflag('P');

    if (TCP_RAND_SPORT)
        sport = ntohs(tcp.fields.sport);

#ifdef SPORT_INCREASE
    if (inc_counter++ >= SPORT_INCREASE_EVERY){
        sport += SPORT_INCREASE_BY;
        tcp.setsport(sport);
        inc_counter = 0;
    }
#endif


    rocket.send(ip/tcp); /* Sending the packet */
    int tries = 0;

    while (tries <= 3){
        rocket.read(buffer, 1024);
        r_ip = rocket.decode_ip(buffer);

        if (r_ip.fields.dst == ip.fields.src) {
            r_tcp = rocket.decode_tcp(buffer + r_ip.length());
            if (r_tcp.fields.sport == tcp.fields.dport){
                if (r_tcp.fields.rst){
                    return false;
                }
                else if (tries >= 3){
                    return true;
                }
            }
            tries++;
        }
    }
    return true;
}


bool TCPScanner::scan_nll(const char *host, uint16_t port){
    tcp.setdport(port); /* Destination Port */
    ip.setdstaddr(host); /* Dest Addr */

    tcp.clearflags(); /* Disable all flags */

    if (TCP_RAND_SPORT)
        sport = ntohs(tcp.fields.sport);

#ifdef SPORT_INCREASE
    if (inc_counter++ >= SPORT_INCREASE_EVERY){
        sport += SPORT_INCREASE_BY;
        tcp.setsport(sport);
        inc_counter = 0;
    }
#endif


    rocket.send(ip/tcp); /* Sending the packet */
    int tries = 0;

    while (tries <= 3){
        rocket.read(buffer, 1024);
        r_ip = rocket.decode_ip(buffer);

        if (r_ip.fields.dst == ip.fields.src) {
            r_tcp = rocket.decode_tcp(buffer + r_ip.length());
            if (r_tcp.fields.sport == tcp.fields.dport){
                if (r_tcp.fields.rst){
                    return false;
                }
                else if (tries >= 3){
                    return true;
                }
            }
            tries++;
        }
    }
    return true;
}

bool TCPScanner::scan_nrm(const char *host, uint16_t port){
    int con_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    int res = connect(con_sock,(struct sockaddr *) &addr, sizeof(addr));
    close (con_sock);
    if (res < 0) return false;
    else return true;
}

bool TCPScanner::scan(const char *host, uint16_t port, char scan_type){
    bool res = false;
    switch(scan_type){
    case 'S':
        res = this->scan_syn(host, port);
        break;
    case 'F':
        res = this->scan_fin(host, port);
        break;
    case 'X':
        res = this->scan_xms(host, port);
        break;
    case 'C':
        res = this->scan_nrm(host, port);
        break;
    case 'N':
        res = this->scan_nll(host, port);
        break;
    }
    return (res ? true: false); /* Because res is a local variable */
}
