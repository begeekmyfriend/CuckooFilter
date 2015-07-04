/*
 * Copyright (C) 2015, Leo Ma <begeekmyfriend@gmail.com>
 */

#ifndef _CUCKOO_DB_H_
#define _CUCKOO_DB_H_

//#define CUKOO_DBG

/* Configuration */
#define SECTOR_SIZE             (1 << 9)  /* 4K bits */
#define NVROM_SIZE              (1 << 15)  /* 256 bits */
#define DAT_LEN                 (SECTOR_SIZE - 20)  /* minus sha1 size */
#define ASSOC_WAY               (4)  /* 4-way association */
#define SLOT_NUM                (NVROM_SIZE / SECTOR_SIZE)
#define BUCKET_NUM              (SLOT_NUM / ASSOC_WAY)

/* Cuckoo hashing */
#define force_align(addr, size) ((void *)((((uintptr_t)(addr)) + (size) - 1) & ~((size) - 1)))
#define cuckoo_hash_lsb(key)    (((size_t *)(key))[0] & (BUCKET_NUM - 1))
#define cuckoo_hash_msb(key)    (((size_t *)(key))[1] & (BUCKET_NUM - 1))

/* Flash driver interfaces. */
#define flash_align(addr)  (!((uintptr_t)(addr) & (SECTOR_SIZE - 1)))
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

/* The log entries store key-value pairs on flash and
 * the size of each entry is assumed to just fit one sector size (4K bits).
 */
struct log_entry {
        uint8_t sha1[20];
        uint8_t data[DAT_LEN];
};

enum { AVAILIBLE, OCCUPIED, DELETED, };

/* The in-memory hash bucket cache is to filter keys (which is assumed SHA1) via
 * cuckoo hash function and map keys to log entries stored on flash.
 */
struct hash_slot_cache {
        uint32_t tag : 30;  /* summary of key */
        uint32_t status : 2;  /* FSM */
        uint32_t offset;  /* offset on flash memory */
};

void put(uint8_t *key, uint8_t *value);
uint8_t *get(uint8_t *key);
void db_init(void);
void usage(const char *str);

#endif /* _CUCKOO_DB_H_ */
