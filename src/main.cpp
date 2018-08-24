#include "layers.hpp"
#include "rocket.hpp"
#include "scanners.hpp"
#include "output.hpp"
#include "utils.hpp"
#include "optsparser.hpp"
#include "protocols/ip.hpp"
#include "protocols/tcp.hpp"

#include <iostream>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <fstream>

/*
 * TODO:
 *  Reduce resources usage
 *  Scan functions
 * opt argv
 * set n_ports, n_host to 1 if theres any host
 * check_port and check_host
 * parse_host and parse_port
 * help
 */

using namespace std;

#define VERBOSE 1

void help();

int main(int argc, char **argv)
{
    utils::checkroot();
    /* Before anything,  Check for options */
    if (argc < 3) /* 3 is the maximum (port, host and the name of program ) */
        help();

    /* Initialize the required variables*/
    uint n_ports, n_hosts;
    vector<uint16_t> ports;
    vector<char *> hosts;
    bool verbose;
    bool syn, con, fin, xms, nll; // Flags
    char opt;

    /* Zeroing some variables */
    syn = con = fin = xms = nll = 0;
    n_ports = n_hosts = 0; /* Starting from 1, this makes it easy to detect errors, when it's zero means theres no host or port*/
    verbose = false;

    /* Parse options */
    while ((opt = getopt(argc, argv, "h:p:nsxcfvCH")) != -1)
    {
        switch (opt)
        {
        case 'h':
            parse_host(optarg, &hosts);
            break;
        case 'p':
            parse_port(optarg, &ports);
            break;
        case 'n':
            nll = 1;
            break;
        case 'x':
            xms = 1;
            break;
        case 'c':
            con = 1;
            break;
        case 'f':
            fin = 1;
            break;
        case 's':
            syn = 1;
            break;
        case 'v':
            verbose = true;
            break;
        case 'C':
            ENABLE_COLORS = ENABLE_COLORS ^ 1; /* toggle colors */
            break;
        case 'H':
            help();
            break;
        default: /* '?' */
            // fatal("Invalid options, if you want to get help, then use -H option!\n");
            // exit(0);
            break;
        }
    }
    /* Setting hosts, and ports count */
    n_hosts = hosts.size();
    n_ports = ports.size();
    /* Check for invalid options */
    if ((syn + nll + xms + con + fin) > 1)
    {
        fatal("You have the right to choose one type of scan!\n");
        exit(EXIT_FAILURE);
    } /* Checks for double scan types */
    if (((syn + nll + xms + con + fin) <= 0) && !utils::checkroot())
    {
        warn("You didn't specifie any scan type!\n");
        note("Using default scan: connect scan! (because you arent't root)\n");
        syn = nll = fin = con = xms = 0;
        con = 1;
    }
    if (((syn + nll + xms + con + fin) <= 0) && utils::checkroot())
    {
        warn("You didn't specifie any scan type!\n");
        note("Using default scan: syn scan! (because you are root)\n");
        syn = nll = fin = con = xms = 0;
        syn = 1;
    }
    if (n_hosts <= 0)
    {
        fatal("You haven't specified any host!\n");
        exit(EXIT_FAILURE);
    } /* Checks if theres any host */
    if (n_ports <= 0)
    {
        note("I'm gonna scan the top 100 ports, because you didn't specifie any ports to scan.\n");
        add_top_100_ports(ports);
    } /* defaults to scan the top 100 ports */
    for (uint x = 0; x <= n_hosts; x++)
    {
        if (!check_host(hosts[x]))
        {
            fatal("Invalid host: ");
            printf("%s!\n", hosts[x]);
            exit(EXIT_FAILURE);
        }
    } /* Checks for an inusual characters in the given host */
    if (n_ports > 0)
    {
        for (uint x = 0; x <= n_ports; x++)
        {
            if (!check_port(ports[x]))
            {
                fatal("Invalid port: ");
                printf("%hu\n", ports[x]);
                exit(EXIT_FAILURE);
            }
        }
    } /* Checks for an invalid tcp port */
    if (((syn + fin + xms + nll) >= 1) && !utils::checkroot())
    {
        note("I'm gonna use connect scan because you aren't the root user\n");
        syn = nll = xms = con = fin = 0;
        con = 1;
    } /* Uses the normal scan if theres no root rights */
    /* Finnished the searching for invalid options */

    /* Setting up flags to be used with scanner.scan */
    char scan_type = 'C';
    if (syn)
    {
        scan_type = 'S';
        if (verbose)
        {
            info("Using syn scan!\n");
        }
    }
    else if (nll)
    {
        scan_type = 'N';
        if (verbose)
        {
            info("Using null scan!\n");
        }
    }
    else if (xms)
    {
        scan_type = 'X';
        if (verbose)
        {
            info("Using xmas scan!\n");
        }
    }
    else if (con)
    {
        scan_type = 'C';
        if (verbose)
        {
            info("Using connect scan!\n");
        }
    }
    else if (fin)
    {
        scan_type = 'F';
        if (verbose)
        {
            info("Using fin scan!\n");
        }
    }

    /* if everything is fine, then preparing to scan */
    TCPScanner scanner;          /* This is the main scanner */
    TreeScan ts[MAX_HOSTS_SCAN]; /* This class, is responsible of representing results as a tree */
    uint n_ts = 0;

    for (uint x = 0; x < n_hosts; x++)
    {
        n_ts = x + 1;
        ts[n_ts - 1].setHost(hosts.at(x));
        if (verbose)
        {
            note("Scanning: ");
            printf("%s ... \n", hosts.at(x));
        }
        for (uint i = 0; i < n_ports; i++)
        {
            if (verbose)
                show_progress(n_ports, i + 1);
            if (scanner.scan(hosts.at(x), ports.at(i), scan_type))
            {
                // n_ts += 1;
                ts[n_ts - 1].addPort(ports.at(i));
            }
        }
    }

    if (n_ts > 0)
    {
        for (uint i = 0; i < n_ts; i++)
            ts[i].show();
        cout << endl;
        exit(EXIT_SUCCESS);
    }
    else
    {
        warn("None of the scanned ports are open!\n");
        exit(EXIT_SUCCESS);
    }

    return 0;
}

void help()
{
    cout << "         .''''''''.        " << " -< nShark v1.0 by h3xbu4n34 (a.k.a ihuomtia) >-" << endl
         << "        /  /o\\ /o\\ \\    " << "Contact me at: ihuomtia at google mail dot com" << endl
         << "       /  /\\/\\/\\/\\/\\    " << "Usage:" << endl
         << "  /---/   \\/\\/\\/\\/\\/  " << "\t\t-h <host[s]> : specify one or more hosts." << endl
         << "  \\  /            /       " << "\t-p <port[s]> : specify one or more ports." << endl
         << "   \\/           /         " << "\t-c           : use connect scan *0 (!R)." << endl
         << "   /          /            " << "\t-s           : use stealth syn scan (R)." << endl
         << "  /         /              " << "\t-n           : use stealth null scan (R)." << endl
         << " /        /                " << "\t-x           : use stealth xmas scan (R)." << endl
         << " |       /                 " << "\t-f           : use stealth fin scan (R)." << endl
         << " \\     /                  " << "\t-C           : disable colors *1." << endl
         << "  \\   /                   " << "\t-v           : be verbose." << endl
         << "   \\  \\                  " << "\t-H           : show this help message." << endl
         << "    \\   \\                " << "Explanation:" << endl
         << "    /     \\               " << "\t(R)          : requires root rights." << endl
         << "   /===|===\\              " << "\t(!R)         : doesn't requires root rights." << endl
         << "   \\/\\/\\/\\/\\/                 " << "\t*0           : this is the default scan if you aren't the root user, otherwise syn." << endl
         << "                            " << "\t*1           : disables colors, this is useful for some terminals." << endl
         << "  (  )  (  )  (  )  )    " << "Examples: " << endl
         << " ()()()()()()()()()()(   " << "\tsyn scan      : nShark -h 127.0.0.1 -p 80,443,22,21 -s -v" << endl
         << "() () () () () () () ()  " << "\tfin scan      : nShark -h 192.168.1.1-255 -p 80-120 -f -v" << endl
         << "()()()()()()()()()()()()(" << "\txmas scan     : nShark -h google.com,youtube.com -p 443,80 -x" << endl
         << "()()()()()()()()()()()()(" << "\tscan all ports: nShark -h 192.168.1.1-255,192.168.4.1/24 -p 0-65535" << endl;
    exit(EXIT_FAILURE);
}
