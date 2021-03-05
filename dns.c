#include <assert.h>
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

static int resolv_name(const char *hostname) {
  int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  /* OpenDNS is currently at 208.67.222.222 (0xd043dede) */
  address.sin_addr.s_addr = htonl(0xd043dede);
  /* DNS runs on port 53 */
  address.sin_port = htons(53);

  /* Copy all fields into a single, concatenated packet */
  size_t packetlen =
      sizeof(dns_header_t) + strlen(hostname) + 2 + sizeof(dns_question_t);
  uint8_t *packet = alloca(packetlen);

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

  /* Send the packet to OpenDNS, then request the response */
  sendto(socketfd, packet, packetlen, 0, (struct sockaddr *)&address,
         (socklen_t)sizeof(address));

  socklen_t length = 0;
  uint8_t response[512];
  memset(&response, 0, 512);

  /* Receive the response from OpenDNS into a local buffer */
  ssize_t bytes = recvfrom(socketfd, response, 512, 0,
                           (struct sockaddr *)&address, &length);
  printf("Received %zd DNS\n", bytes);

  dns_header_t *response_header = (dns_header_t *)response;
  if ((ntohs(response_header->flags) & 0xf) != 0) {
    return 1;
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

  return 0;
}

int main() { resolv_name("ya.ru"); }
