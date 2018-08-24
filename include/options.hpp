/**
 * @file options.hpp
 * @brief Defines various constants and macros for packet handling options.
 *
 * @author ihuomtia
 * @date 24-08-2018
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#define DEBUG

/* Packet IDs */
#define IP_PACKET_ID 0
#define TCP_PACKET_ID 1


/* Other options */
#define CALC_TCP_CHECKSUM 1
#define CALC_IP_LENGTH    1
#define SET_IP_PROTOCOL   1
#define TCP_RAND_SEQ      1
#define TCP_RAND_SPORT    1
#define COMPILE_PACKET_LAYERING 1
#define CLEAN_BEFORE_COMPILE    1

/* Increasing source port by SPORT_INCRESE_BY every SPORT_INCREASE_EVERY if SPORT_INCREASE */
#define SPORT_INCREASE 1
#define SPORT_INCREASE_BY 1
#define SPORT_INCREASE_EVERY 100


/* For scanning */
#define MAX_HOSTS_SCAN 1024
#define MAX_PORTS_SCAN 65536  /* You can decrease this to reduce memory usage */

/* Enable colors */
static bool ENABLE_COLORS = 1;

#define DEFAULT_TCP_SPORT 1024
#define DEFAULT_TCP_SEQ 31337

#endif // OPTIONS_H
