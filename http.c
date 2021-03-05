#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
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

int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen, unsigned int timeout_ms) {
  int rc = 0;
  // Set O_NONBLOCK
  int sockfd_flags_before;
  if ((sockfd_flags_before = fcntl(sockfd, F_GETFL, 0) < 0))
    return -1;
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before | O_NONBLOCK) < 0)
    return -1;
  // Start connecting (asynchronously)
  do {
    if (connect(sockfd, addr, addrlen) < 0) {
      // Did connect return an error? If so, we'll fail.
      if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
        rc = -1;
      }
      // Otherwise, we'll wait for it to complete.
      else {
        // Set a deadline timestamp 'timeout' ms from now (needed b/c poll can
        // be interrupted)
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
          rc = -1;
          break;
        }
        struct timespec deadline = {.tv_sec = now.tv_sec,
                                    .tv_nsec =
                                        now.tv_nsec + timeout_ms * 1000000l};
        // Wait for the connection to complete.
        do {
          // Calculate how long until the deadline
          if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            rc = -1;
            break;
          }
          int ms_until_deadline =
              (int)((deadline.tv_sec - now.tv_sec) * 1000l +
                    (deadline.tv_nsec - now.tv_nsec) / 1000000l);
          if (ms_until_deadline < 0) {
            rc = 0;
            break;
          }
          // Wait for connect to complete (or for the timeout deadline)
          struct pollfd pfds[] = {{.fd = sockfd, .events = POLLOUT}};
          rc = poll(pfds, 1, ms_until_deadline);
          // If poll 'succeeded', make sure it *really* succeeded
          if (rc > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (retval == 0)
              errno = error;
            if (error != 0)
              rc = -1;
          }
        }
        // If poll was interrupted, try again.
        while (rc == -1 && errno == EINTR);
        // Did poll timeout? If so, fail.
        if (rc == 0) {
          errno = ETIMEDOUT;
          rc = -1;
        }
      }
    }
  } while (0);
  // Restore original O_NONBLOCK state
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before) < 0)
    return -1;
  // Success
  return rc;
}

#define CONNECT_TIMEOUT 3000 // milliseconds

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

    if (connect_with_timeout(s, (struct sockaddr *)&addr, sizeof(addr),
                             CONNECT_TIMEOUT) == 1) {
      ret = ERR_GENERAL;
      break;
    }
    close(s);
    s = socket(AF_INET, SOCK_STREAM, 0);
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
