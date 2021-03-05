#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dns.h"
#include "http.h"

#define ERR_GENERAL 1
#define ERR_SOCKET 2
#define ERR_GETADDRINFO 3
#define ERR_CONNECT 4
#define ERR_SEND 5
#define ERR_USAGE 6

#define NDEBUG

static int get_http_respcode(const char *inpbuf) {
  char proto[4096], descr[4096];
  int code;

  if (sscanf(inpbuf, "%s %d %s", proto, &code, descr) < 2)
    return -1;
  return code;
}

#undef NDEBUG

int download(char *hostname, char *uri, nservers_t *ns, int writefd) {
  int ret = ERR_GENERAL;

  a_records_t srv;
  if (!resolv_name(ns, hostname, &srv)) {
    return ERR_GETADDRINFO;
  }

  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);

  for (int i = 0; i < srv.len; i++) {
    memcpy(&addr.sin_addr, &srv.ipv4_addr[i], sizeof(uint32_t));

#ifndef NDEBUG
    char buf[256];
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    fprintf(stderr, "Connecting to %s...\n", buf);
#endif

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      ret = ERR_GENERAL;
      break;
    }
    ret = ERR_CONNECT;
  }

  if (ret == ERR_CONNECT) {
    return ret;
  }

  char buf[4096];
  // use the hack to save some space in .rodata
  strcpy(buf, "GET /");
  if (uri) {
    strncat(buf, uri, sizeof(buf) - strlen(buf) - 1);
  }
  strncat(buf, " HTTP/1.0\r\nHost: ", sizeof(buf) - strlen(buf) - 1);
  strncat(buf, hostname, sizeof(buf) - strlen(buf) - 1);
  strncat(buf, "\r\n\r\n", sizeof(buf) - strlen(buf) - 1);
  int tosent = strlen(buf);
  int nsent = send(s, buf, tosent, 0);
  if (nsent != tosent)
    return ERR_SEND;

  int header = 1;
  int nrecvd;
  while ((nrecvd = recv(s, buf, sizeof(buf), 0))) {
    char *ptr = buf;
    if (header) {
      ptr = strstr(buf, "\r\n\r\n");
      if (!ptr)
        continue;

      int rcode = get_http_respcode(buf);
      if (rcode / 100 != 2)
        return rcode / 100 * 10 + rcode % 10;

      header = 0;
      ptr += 4;
      nrecvd -= ptr - buf;
    }
    write(writefd, ptr, nrecvd);
  }

  return 0;
}
