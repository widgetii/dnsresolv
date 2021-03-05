#ifndef DNS_H
#define DNS_H

#define MAX_NSERVERS 16
typedef struct {
  uint32_t ipv4_addr[MAX_NSERVERS];
  size_t len;
} nservers_t;

#define MAX_ARECORDS 16
typedef struct {
  uint32_t ipv4_addr[MAX_ARECORDS];
  size_t len;
} a_record_t;


#endif /* DNS_H */
