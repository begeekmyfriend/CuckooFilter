/*
 * Copyright (C) 2015, Leo Ma <begeekmyfriend@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "cuckoo_hash.h"

static uint8_t *nvrom_base_addr;
static struct hash_slot_cache **hash_buckets;
static struct hash_slot_cache *hash_slots;
static uint32_t hash_slot_num;
static uint32_t hash_bucket_num;
static uint32_t log_entries;

void usage(const char *s)
{
        fprintf(stderr, "usage: %s\n", s);
}

static void dump_sha1_key(uint8_t *sha1)
{
        int i;
        static const char str[] = "0123456789abcdef";

        printf("sha1: ");
        for (i = 19; i >= 0; i--) {
                putchar(str[sha1[i] >> 4]);
                putchar(str[sha1[i] & 0xf]);
        }
        putchar('\n');
}

static uint32_t next_entry_offset(void)
{
        uintptr_t append_addr = (uintptr_t)nvrom_base_addr + log_entries * sizeof(struct log_entry);
        assert(flash_align(append_addr));
        if (++log_entries * sizeof(struct log_entry) >= NVROM_SIZE) {
                printf("Out of flash memory!\n");
                exit(-1);
        }
        return (uint32_t)(append_addr - (uintptr_t)nvrom_base_addr);
}

static void show_hash_slots(void)
{
        int i, j;

        printf("List all keys in hash table (key/value):\n");
        for (i = 0; i < hash_bucket_num; i++) {
                printf("bucket[%04x]:", i);
                struct hash_slot_cache *slot = hash_buckets[i];
                for (j = 0; j < ASSOC_WAY; j++) {
                        printf("\t%04x/%08x", slot[j].tag, slot[j].offset);
                }
                printf("\n");
        }
}

static uint8_t * key_verify(uint8_t *key, uint32_t offset)
{
        int i;
        uint8_t *read_addr = nvrom_base_addr + offset;
        for (i = 0; i < 20; i++) {
                if (key[i] != flash_read(read_addr)) {
                        return NULL;
                }
                read_addr++;
        }
        return read_addr;
}

uint8_t *cuckoo_hash_get(uint8_t *key)
{
        int i, j;
        uint8_t *read_addr;
        uint32_t tag[2], offset;
        static uint8_t value[DAT_LEN];
        struct hash_slot_cache *hash_slot;

        tag[0] = cuckoo_hash_lsb(key, hash_bucket_num);
        tag[1] = cuckoo_hash_msb(key, hash_bucket_num);

#ifdef CUKOO_DBG
        printf("get t0:%x t1:%x\n", tag[0], tag[1]);
        dump_sha1_key(key);
#endif

        /* Filter the key and verify if it exists. */
        hash_slot = hash_buckets[tag[0]];
        for (i = 0; i < ASSOC_WAY; i++) {
                if (cuckoo_hash_msb(key, hash_bucket_num) == hash_slot[i].tag) {
                        assert(hash_slot[i].status == OCCUPIED);
                        offset = hash_slot[i].offset;
                        read_addr = key_verify(key, offset);
                        if (read_addr != NULL) {
                                break;
                        }
                }
        }

        if (i == ASSOC_WAY) {
                hash_slot = hash_buckets[tag[1]];
                for (j = 0; j < ASSOC_WAY; j++) {
                        if (cuckoo_hash_lsb(key, hash_bucket_num) == hash_slot[j].tag) {
                                assert(hash_slot[j].status == OCCUPIED);
                                offset = hash_slot[j].offset;
                                read_addr = key_verify(key, offset);
                                if (read_addr != NULL) {
                                        break;
                                }
                        }
                }
                if (j == ASSOC_WAY) {
                        printf("Key not exists!\n");
                        return NULL;
                } 
        }

        /* Read data from the log entry on flash. */
        for (i = 0; i < DAT_LEN; i++) {
                value[i] = flash_read(read_addr);
                read_addr++;
        }

        return value;
}

static int hash_put(uint8_t *key, uint32_t offset)
{
        uint32_t tag[2], old_tag[2], old_offset;
        uint32_t i, j, k, alt_cnt;
        struct hash_slot_cache *hash_slot;

        tag[0] = cuckoo_hash_lsb(key, hash_bucket_num);
        tag[1] = cuckoo_hash_msb(key, hash_bucket_num);

#ifdef CUKOO_DBG
        printf("put offset:%x t0:%x t1:%x\n", offset, tag[0], tag[1]);
        dump_sha1_key(key);
#endif

        /* Insert new key into hash buckets. */
        hash_slot = hash_buckets[tag[0]];
        for (i = 0; i < ASSOC_WAY; i++) {
                if (hash_slot[i].status == AVAILIBLE) {
                        hash_slot[i].status = OCCUPIED;
                        hash_slot[i].tag = cuckoo_hash_msb(key, hash_bucket_num);
                        hash_slot[i].offset = offset;
                        break;
                }
        }

        if (i == ASSOC_WAY) {
                hash_slot = hash_buckets[tag[1]];
                for (j = 0; j < ASSOC_WAY; j++) {
                        if (hash_slot[j].status == AVAILIBLE) {
                                hash_slot[j].status = OCCUPIED;
                                hash_slot[j].tag = cuckoo_hash_lsb(key, hash_bucket_num);
                                hash_slot[j].offset = offset;
                                break;
                        }
                }

                if (j == ASSOC_WAY) {
                        /* Hash collision, kick out the old bucket and
                         * move it to the alternative bucket and go on inserting.
                         */
                        hash_slot = hash_buckets[tag[0]];
                        old_tag[0] = tag[0];
                        old_tag[1] = hash_slot[0].tag;
                        old_offset = hash_slot[0].offset;
                        hash_slot[0].tag = tag[1];
                        hash_slot[0].offset = offset;
                        i = 0 ^ 1;
                        alt_cnt = 0;
                        k = 0;

KICK_OUT:
                        hash_slot = hash_buckets[old_tag[i]];
                        for (j = 0; j < ASSOC_WAY; j++) {
                                if (hash_slot[j].status == AVAILIBLE) {
                                        hash_slot[j].status = OCCUPIED;
                                        hash_slot[j].tag = old_tag[i ^ 1];
                                        hash_slot[j].offset = old_offset;
                                        break;
                                }
                        }

                        if (j == ASSOC_WAY) {
                                if (++alt_cnt > 128) {
                                        if (k == ASSOC_WAY - 1) {
                                                /* Hash table is almost full and needs to be resized */
                                                return -1;
                                        } else {
                                                k++;
                                        }
                                }
                                uint32_t tmp_tag = hash_slot[k].tag;
                                uint32_t tmp_offset = hash_slot[k].offset;
                                hash_slot[k].tag = old_tag[i ^ 1];
                                hash_slot[k].offset = old_offset;
                                old_tag[i ^ 1] = tmp_tag;
                                old_offset = tmp_offset;
                                i ^= 1;
                                goto KICK_OUT;
                        }
                }
        }

#ifdef CUKOO_DBG
        show_hash_slots();
#endif

        return 0;
}

int cuckoo_hash_put(uint8_t *key, uint8_t *value)
{
        int i;

        /* Find new log entry offset on flash. */
        uint32_t offset = next_entry_offset();

        /* Insert into hash slots */
        int ret = hash_put(key, offset);
        if (ret == -1) {
                return -1;
        }

        /* Add new entry of key-value pair on flash. */
        uint8_t *append_addr = nvrom_base_addr + offset;
        assert(flash_align(append_addr));
        flash_sector_erase(append_addr);
        for (i = 0; i < 20; i++) {
                flash_write(append_addr, key[i]);
                append_addr++;
        }
        for (i = 0; i < DAT_LEN; i++) {
                flash_write(append_addr, value[i]);
                append_addr++;
        }

        return 0;
}

void cuckoo_rehash(void)
{
        int i;
        uint32_t entries, offset;
        uint8_t *read_addr, key[20];

        /* Reallocate hash slots */
        hash_slot_num *= 2;
        hash_slots = realloc(hash_slots, hash_slot_num * sizeof(struct hash_slot_cache));
        if (hash_slots == NULL) {
                return;
        }
        memset(hash_slots, 0, hash_slot_num * sizeof(struct hash_slot_cache));

        /* Reallocate hash buckets associated with slots */
        hash_bucket_num *= 2;
        hash_buckets = realloc(hash_buckets, hash_bucket_num * sizeof(struct hash_slot_cache *));
        if (hash_buckets == NULL) {
                free(hash_slots);
                return;
        }
        for (i = 0; i < hash_bucket_num; i++) {
                hash_buckets[i] = &hash_slots[i * ASSOC_WAY];
        }

        /* Re-insert all entries from nvrom */
        read_addr = nvrom_base_addr;
        entries = log_entries;
        while (entries--) {
                offset = read_addr - nvrom_base_addr;
                for (i = 0; i < 20; i++) {
                        key[i] = flash_read(read_addr);
                        read_addr++;
                }
                hash_put(key, offset);
                read_addr += DAT_LEN;
        }
}

int cuckoo_hash_init(void)
{
        int i;

        /* Whole flash memory space */
        nvrom_base_addr = malloc(NVROM_SIZE + SECTOR_SIZE);
        if (nvrom_base_addr == NULL) {
                return -1;
        }
        nvrom_base_addr = force_align(nvrom_base_addr, SECTOR_SIZE);

        /* Allocate hash slots */
        hash_slot_num = NVROM_SIZE / SECTOR_SIZE;
        hash_slots = calloc(hash_slot_num, sizeof(struct hash_slot_cache));
        if (hash_slots == NULL) {
                return -1;
        }

        /* Allocate hash buckets associated with slots */
        hash_bucket_num = hash_slot_num / ASSOC_WAY;
        hash_buckets = malloc(hash_bucket_num * sizeof(struct hash_slot_cache *));
        if (hash_buckets == NULL) {
                free(hash_slots);
                return -1;
        }
        for (i = 0; i < hash_bucket_num; i++) {
                hash_buckets[i] = &hash_slots[i * ASSOC_WAY];
        }

        return 0;
}
