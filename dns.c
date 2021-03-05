#include <assert.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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

#include "tools.h"

typedef struct {
  uint16_t xid;     /* Randomly chosen identifier */
  uint16_t flags;   /* Bit-mask to indicate request/response */
  uint16_t qdcount; /* Number of questions */
  uint16_t ancount; /* Number of answers */
  uint16_t nscount; /* Number of authority records */
  uint16_t arcount; /* Number of additional records */
} __attribute__((packed)) dns_header_t;

typedef struct {
  uint16_t dnstype;  /* The QTYPE (1 = A) */
  uint16_t dnsclass; /* The QCLASS (1 = IN) */
} __attribute__((packed)) dns_question_t;

/* Structure of the bytes for an IPv4 answer */
typedef struct {
  uint16_t compression;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t length;
  struct in_addr addr;
} __attribute__((packed)) dns_record_a_t;

#define MAX_NSERVERS 16
typedef struct {
  uint32_t ipv4_addr[MAX_NSERVERS];
  size_t len;
} nservers_t;

static void parse_resolv_conf(nservers_t *ns) {
  FILE *f = fopen("/etc/resolv.conf", "r");

  char *line = NULL;
  size_t len = 0, i = ns->len;
  ssize_t read;
  uint8_t *d = (uint8_t *)&ns->ipv4_addr;

  while ((read = getline(&line, &len, f)) != -1) {
    if (sscanf(line, "nameserver %hhd.%hhd.%hhd.%hhd", &d[0], &d[1], &d[2],
               &d[3]) == 4) {
      if (i == MAX_NSERVERS)
        break;
      d = (uint8_t *)&ns->ipv4_addr[++i];
    };
  }
  if (line)
    free(line);

exit:
  fclose(f);
  ns->len = i;
}

static void fill_dns_req(uint8_t *packet, size_t packetlen,
                         const char *hostname) {
  /* Set up the DNS header */
  dns_header_t *header = (dns_header_t *)packet;
  memset(header, 0, sizeof(dns_header_t));
  header->xid = htons(0x1234);   /* Randomly chosen ID */
  header->flags = htons(0x0100); /* Q=0, RD=1 */
  header->qdcount = htons(1);    /* Sending 1 question */

  /* Set up the DNS question */
  dns_question_t *question =
      (dns_question_t *)(packet + packetlen - sizeof(dns_question_t));
  question->dnstype = htons(1);  /* QTYPE 1=A */
  question->dnsclass = htons(1); /* QCLASS 1=IN */

  char *question_name = (char *)packet + sizeof(dns_header_t);

  /* Leave the first byte blank for the first field length */
  strcpy(question_name + 1, hostname);
  uint8_t *prev = (uint8_t *)question_name;
  uint8_t count = 0; /* Used to count the bytes in a field */

  /* Traverse through the name, looking for the . locations */
  for (size_t i = 0; i < strlen(hostname); i++) {
    /* A . indicates the end of a field */
    if (hostname[i] == '.') {
      /* Copy the length to the byte before this field, then
         update prev to the location of the . */
      *prev = count;
      prev = (uint8_t *)question_name + i + 1;
      count = 0;
    } else
      count++;
  }
  *prev = count;
}

static bool parse_dns_resp(uint8_t *response) {
  dns_header_t *response_header = (dns_header_t *)response;
  if ((ntohs(response_header->flags) & 0xf) != 0) {
    return false;
  }

  /* Get a pointer to the start of the question name, and
     reconstruct it from the fields */
  uint8_t *start_of_name = (uint8_t *)(response + sizeof(dns_header_t));
  uint8_t total = 0;
  uint8_t *field_length = start_of_name;
  while (*field_length != 0) {
    /* Restore the dot in the name and advance to next length */
    total += *field_length + 1;
    *field_length = '.';
    field_length = start_of_name + total;
  }
  *field_length = '\0'; /* Null terminate the name */

  dns_record_a_t *rec = (dns_record_a_t *)(field_length + 5);
  printf("record: %s\n", start_of_name + 1);
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &rec->addr, buf, sizeof(buf));
  printf("IP: %s\n", buf);

  return true;
}

#define MAX_DNS_PACKET 512
static bool resolv_name(nservers_t *ns, const char *hostname) {
  int socketfd = socket(AF_INET, SOCK_DGRAM, 0);

  /* Copy all fields into a single, concatenated packet */
  size_t packetlen =
      sizeof(dns_header_t) + strlen(hostname) + 2 + sizeof(dns_question_t);
  uint8_t *packet = alloca(packetlen);

  fill_dns_req(packet, packetlen, hostname);

  struct sockaddr_in address;
  address.sin_family = AF_INET;
  /* DNS runs on port 53 */
  address.sin_port = htons(53);

  for (int i = 0; i < ns->len; i++) {
    address.sin_addr.s_addr = ns->ipv4_addr[i];
  }

  /* Send the packet to DNS server, then request the response */
  sendto(socketfd, packet, packetlen, 0, (struct sockaddr *)&address,
         (socklen_t)sizeof(address));

  socklen_t length = 0;
  uint8_t response[MAX_DNS_PACKET];
  memset(&response, 0, MAX_DNS_PACKET);

  /* Receive the response from DNS server into a local buffer */
  ssize_t bytes = recvfrom(socketfd, response, MAX_DNS_PACKET, 0,
                           (struct sockaddr *)&address, &length);
  printf("Received %zd DNS\n", bytes);

  if (!parse_dns_resp(response))
    return false;

  return true;
}

static void add_predefined_ns(nservers_t *ns, ...) {
  va_list ap;
  int argno = 0;
  uint32_t ipv4_addr;

  va_start(ap, ns);
  while ((ipv4_addr = va_arg(ap, uint32_t)) && ns->len < MAX_NSERVERS) {
    ns->ipv4_addr[ns->len++] = ipv4_addr;
  }
  va_end(ap);
}

int main() {
  nservers_t ns;
  ns.len = 0;

  add_predefined_ns(&ns, 0xd043dede /* 208.67.222.222 */,
                    0x01010101 /* 1.1.1.1 */, 0);
  parse_resolv_conf(&ns);

  for (int i = 0; i < ns.len; i++) {
    printf("%X\n", ntohl(ns.ipv4_addr[i]));
  }
  resolv_name(&ns, "ya.ru");
}
