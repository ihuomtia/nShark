/**
 * @file output.hpp
 * @brief Uitlity functions for printing out messages
 *
 * This header provides a set of functions for performing various
 * stdout coloring and message printing operations.
 *
 * @author ihuomtia
 * @date 24-08-2018
 */
#ifndef OUTPUT_HPP
#define OUTPUT_HPP

#include "options.hpp"

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <map>

/* Ansi Colors And Styles */
/* To get them use this in Unix terminal: for i in {0..99}; do echo -e
 * '\e['$i'm' '\\033['$i'm' '\e[0m'; done " */

/* Styles */
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define ITALIC "\033[3m"
#define UNDERLINE "\033[4m"
#define POPING "\033[5m"
#define NEGATIVE "\033[7m"
#define STRIKETROUGH "\033[9m"
#define ABOVELINE "\033[53m"
/* Dark Colors */
#define DARK_BLACK "\033[30m"
#define DARK_RED "\033[31m"
#define DARK_GREEN "\033[32m"
#define DARK_ORANGE "\033[33m"
#define DARK_BLUE "\033[34m"
#define DARK_MAGENTA "\033[35m"
#define DARK_CYAN "\033[36m"
#define DARK_WHITE "\033[37m"
/* Background colors */
#define BACK_BLACK "\033[40m"
#define BACK_RED "\033[41m"
#define BACK_GREEN "\033[42m"
#define BACK_ORANGE "\033[43m"
#define BACK_BLUE "\033[44m"
#define BACK_MAGENTA "\033[45m"
#define BACK_CYAN "\033[46m"
#define BACK_WHITE "\033[47m"
/* Light colors */
#define BLACK "\033[90m"
#define RED "\033[91m"
#define GREEN "\033[92m"
#define YELLOW "\033[93m"
#define BLUE "\033[94m"
#define MAGENTA "\033[95m"
#define CYAN "\033[96m"
#define WHITE "\033[97m"
/* redefining for clearance */
#define LIGHT_BLACK BLACK
#define LIGHT_RED RED
#define LIGHT_GREEN GREEN
#define LIGHT_ORANGE YELLOW
#define LIGHT_MAGENTA MAGENTA
#define LIGHT_CYAN CYAN
#define LIGHT_WHITE WHITE

/* Functions */
inline void col(const char *color)
{
  /* This function takes care of enabling or disabling colors */
  if (ENABLE_COLORS)
    printf("%s", color);
}

inline void fatal(const char *msg)
{
  col(BOLD);
  col(WHITE);
  printf("[");
  col(BACK_RED);
  printf("ERR");
  col(RESET);
  col(BOLD);
  col(WHITE);
  printf("] ");
  printf("%s", msg);
  col(RESET);
}
inline void success(const char *msg)
{
  col(BOLD);
  col(WHITE);
  printf("[");
  col(GREEN);
  printf(" + ");
  col(RESET);
  col(BOLD);
  col(WHITE);
  printf("] ");
  printf("%s", msg);
  col(RESET);
}
inline void info(const char *msg)
{
  col(BOLD);
  col(WHITE);
  printf("[");
  col(POPING);
  col(BLUE);
  printf(" i ");
  col(RESET);
  col(BOLD);
  col(WHITE);
  printf("] ");
  printf("%s", msg);
  col(RESET);
}
inline void warn(const char *msg)
{
  col(BOLD);
  col(WHITE);
  printf("[");
  col(YELLOW);
  printf(" ! ");
  col(RESET);
  col(BOLD);
  col(WHITE);
  printf("] ");
  printf("%s", msg);
  col(RESET);
}
inline void note(const char *msg)
{
  col(BOLD);
  col(WHITE);
  printf("[");
  col(YELLOW);
  printf(" ~ ");
  col(RESET);
  col(BOLD);
  col(WHITE);
  printf("] ");
  printf("%s", msg);
  col(RESET);
}

void show_progress(int total, int current)
{
  int percent = (current * 100) / total;
  note("Percentage: ");
  printf("%d %%\r", percent);
}

/* Scanner output */
class TreeScan
{
public:
  TreeScan()
  {
    memset(host, 0x0, 32);
  }
  inline void addPort(uint16_t port) { ports.push_back(port); }
  inline void setHost(const char tgt[])
  {
    /* FIXME: this is obviously vulnerable XD */
    int i;
    for (i = 0; tgt[i] != '\0'; i++)
      host[i] = tgt[i];
    host[i] = '\0';
  }
  void show()
  {
    uint i;
    if (host)
    {
      int identation = strlen(host) + 4;
      col(WHITE);
      col(BOLD);
      printf("\n[");
      col(NEGATIVE);
      col(WHITE);
      printf("%s", host);
      col(RESET);
      col(BOLD);
      col(WHITE);
      printf("]");
      col(GREEN);
      printf("<-");
      col(CYAN);
      printf("|\n");

      for (i = 0; i < ports.size(); i++)
      {
        printf("%*s", identation, "");
        col(RESET);
        col(CYAN);

        printf("|__/ ");
        col(WHITE);
        col(BOLD);
        printf(" Port ");
        col(RED);
        printf("%-5d ", ports.at(i));
        col(CYAN);
        printf(" \\__ ");
        col(RESET);
        // col(CYAN);
        // printf(" TCP ");
        col(ITALIC);
        col(YELLOW);
        printf("port is open.\n");
        col(RESET);
      }
      if (ports.size() <= 0)
      {
        printf("%*s", identation, "");
        col(RESET);
        col(CYAN);
        printf("|__/");
        col(RED);
        col(BOLD);
        col(ITALIC);
        col(ABOVELINE);
        printf(" None of the scanned ports is open! ");
        col(RESET);
        col(CYAN);
        printf(" \\__\n");
        col(RESET);
      }
      col(CYAN);
      printf("%*s", identation, "");
      printf("|___________________________________________|\n");
      col(RESET);
    }
  }

  char host[32];
  std::vector<uint16_t> ports;
};

#endif // OUTPUT_HPP
