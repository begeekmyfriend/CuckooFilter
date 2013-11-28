#ifndef _KV_DB_H_
#define _KV_DB_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define SECTOR_SIZE  (1 << 9)  // 4K bits
#define NVROM_SIZE  (1 << 14)  // 128K bits
#define DAT_LEN  (SECTOR_SIZE - 20)  // minus sha1 size
#define ASSOC_WAY  4  // 4-way association.
#define SLOT_NUM  (NVROM_SIZE / SECTOR_SIZE)
#define BUCKET_NUM  (SLOT_NUM / ASSOC_WAY)
#define force_align(addr, size)  ((((uint32_t)(addr)) + (size) - 1) & ~((size) - 1))
#define tag2idx(tag)  ((tag) & 0x7)
#define cuckoo_hash_lsb(key)  (((uint8_t *)(key))[1] & 0x7)
#define cuckoo_hash_msb(key)  (((uint8_t *)(key))[3] & 0x7)
#define set_tag_lsb(key, tag)  ((tag) = (((((uint8_t *)(key))[0] & 0x3f) << 8) | (((uint8_t *)(key))[1] & 0xff)))
#define set_tag_msb(key, tag)  ((tag) = (((((uint8_t *)(key))[2] & 0x3f) << 8) | (((uint8_t *)(key))[3] & 0xff)))
#define key_match_lsb(key, tag)  ((tag) == (((((uint8_t *)(key))[0] & 0x3f) << 8) | (((uint8_t *)(key))[1] & 0xff)))
#define key_match_msb(key, tag)  ((tag) == (((((uint8_t *)(key))[2] & 0x3f) << 8) | (((uint8_t *)(key))[3] & 0xff)))

// Flash driver interface.
#define flash_align(addr)  (!((uint32_t)(addr) & (SECTOR_SIZE - 1)))
#define flash_read(addr)  (*(volatile uint8_t *)(addr))
#define flash_write(addr, byte)  (*(volatile uint8_t *)(addr) = (byte))
#define flash_sector_erase(addr) \
  do { \
    uint32_t __i; \
    volatile uint8_t *__addr = (volatile uint8_t *)(addr); \
    for (__i = 0; __i < SECTOR_SIZE; __i++) { \
      *(volatile uint8_t *)__addr = 0xff; \
      __addr++; \
    } \
  } while (0)

// The log entries store key-value pairs on flash and
// the size of each entry is assumed to just fit one sector size (4K bits).
struct log_entry {
  uint8_t sha1[20];
  uint8_t data[DAT_LEN];
};

enum { AVAILIBLE, OCCUPIED, DELETED, };

// The in-memory hash bucket cache is to filter keys (which is assumed SHA1) via
// cuckoo hash function and map keys to log entries stored on flash.
struct hash_slot_cache {
  uint16_t tag : 14;  // summary of key
  uint16_t status : 2;  // FSM
  uint16_t offset;  // offset on flash memory, occupancy of 13 bits (total 128K bits assumed)
};

static inline void dump_sha1_key(uint8_t *sha1)
{
  static const uint8_t str[] = "0123456789abcdef";
  uint8_t i;

  printf("sha1: ");
  for (i = 0; i < 20; i++)
  {
    putchar(str[sha1[i] >> 4]);
    putchar(str[sha1[i] & 0xf]);
  }
  putchar('\n');
}

extern void put(uint8_t *key, uint8_t *value);
extern uint8_t *get(uint8_t *key);
extern void db_init();
extern void usage(const char *str);

#endif /* _KV_DB_H_ */
