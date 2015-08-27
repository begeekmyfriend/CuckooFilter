/*
 * Copyright (C) 2015, Leo Ma <begeekmyfriend@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "cuckoo_filter.h"

struct hash_table {
        struct hash_slot_cache **buckets;
        struct hash_slot_cache *slots;
        uint32_t slot_num;
        uint32_t bucket_num;
};

static uint8_t *nvrom_base_addr;
static uint32_t nvrom_size;
static uint32_t log_entries;
static struct hash_table hash_table;

static void dump_sha1_key(uint8_t *sha1)
{
#ifdef CUCKOO_DBG
        int i;
        static const char str[] = "0123456789abcdef";

        printf("SHA1: ");
        for (i = 19; i >= 0; i--) {
                putchar(str[sha1[i] >> 4]);
                putchar(str[sha1[i] & 0xf]);
        }
        putchar('\n');
#endif
}

static uint32_t next_entry_offset(void)
{
        uint8_t *append_addr = nvrom_base_addr + log_entries * sizeof(struct log_entry);
        assert(flash_align(append_addr));
        if ((log_entries + 1) * sizeof(struct log_entry) >= nvrom_size) {
                return INVALID_OFFSET;
        } else {
                return (uint32_t)(append_addr - nvrom_base_addr);
        }
}

static void show_hash_slots(struct hash_table *table)
{
#ifdef CUCKOO_DBG
        int i, j;

        printf("List all keys in hash table (tag/status/offset):\n");
        for (i = 0; i < table->bucket_num; i++) {
                printf("bucket[%04x]:", i);
                struct hash_slot_cache *slot = table->buckets[i];
                for (j = 0; j < ASSOC_WAY; j++) {
                        printf("\t%04x/%x/%08x", slot[j].tag, slot[j].status, slot[j].offset);
                }
                printf("\n");
        }
#endif
}

static uint8_t *key_verify(uint8_t *key, uint32_t offset)
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

static int cuckoo_hash_collide(struct hash_table *table, uint32_t *tag, uint32_t *p_offset)
{
        int i, j, k, alt_cnt;
        uint32_t old_tag[2], offset, old_offset;
        struct hash_slot_cache *slot;

        /* Kick out the old bucket and move it to the alternative bucket. */
        offset = *p_offset;
        slot = table->buckets[tag[0]];
        old_tag[0] = tag[0];
        old_tag[1] = slot[0].tag;
        old_offset = slot[0].offset;
        slot[0].tag = tag[1];
        slot[0].offset = offset;
        i = 0 ^ 1;
        k = 0;
        alt_cnt = 0;

KICK_OUT:
        slot = table->buckets[old_tag[i]];
        for (j = 0; j < ASSOC_WAY; j++) {
                if (offset == INVALID_OFFSET && slot[j].status == DELETED) {
                        slot[j].status = OCCUPIED;
                        slot[j].tag = old_tag[i ^ 1];
                        *p_offset = offset = slot[j].offset;
                        break;
                } else if (slot[j].status == AVAILIBLE) {
                        slot[j].status = OCCUPIED;
                        slot[j].tag = old_tag[i ^ 1];
                        slot[j].offset = old_offset;
                        break;
                }
        }

        if (j == ASSOC_WAY) {
                if (++alt_cnt > 128) {
                        if (k == ASSOC_WAY - 1) {
                                /* Hash table is almost full and needs to be resized */
                                return 1;
                        } else {
                                k++;
                        }
                }
                uint32_t tmp_tag = slot[k].tag;
                uint32_t tmp_offset = slot[k].offset;
                slot[k].tag = old_tag[i ^ 1];
                slot[k].offset = old_offset;
                old_tag[i ^ 1] = tmp_tag;
                old_offset = tmp_offset;
                i ^= 1;
                goto KICK_OUT;
        }

        return 0;
}

static int cuckoo_hash_get(struct hash_table *table, uint8_t *key, uint8_t **read_addr)
{
        int i, j;
        uint8_t *addr;
        uint32_t tag[2], offset;
        struct hash_slot_cache *slot;

        tag[0] = cuckoo_hash_lsb(key, table->bucket_num);
        tag[1] = cuckoo_hash_msb(key, table->bucket_num);

#ifdef CUCKOO_DBG
        printf("get t0:%x t1:%x\n", tag[0], tag[1]);
#endif
        dump_sha1_key(key);

        /* Filter the key and verify if it exists. */
        slot = table->buckets[tag[0]];
        for (i = 0; i < ASSOC_WAY; i++) {
                if (cuckoo_hash_msb(key, table->bucket_num) == slot[i].tag) {
                        if (slot[i].status == OCCUPIED) {
                                offset = slot[i].offset;
                                addr = key_verify(key, offset);
                                if (addr != NULL) {
                                        if (read_addr != NULL) {
                                                *read_addr = addr;
                                        }
                                        break;
                                }
                        } else if (slot[i].status == DELETED) {
#ifdef CUCKOO_DBG
                                printf("Key has been deleted!\n");
#endif
                                return DELETED;
                        }
                }
        }

        if (i == ASSOC_WAY) {
                slot = table->buckets[tag[1]];
                for (j = 0; j < ASSOC_WAY; j++) {
                        if (cuckoo_hash_lsb(key, table->bucket_num) == slot[j].tag) {
                                if (slot[j].status == OCCUPIED) {
                                        offset = slot[j].offset;
                                        addr = key_verify(key, offset);
                                        if (addr != NULL) {
                                                if (read_addr != NULL) {
                                                        *read_addr = addr;
                                                }
                                                break;
                                        }
                                } else if (slot[j].status == DELETED) {
#ifdef CUCKOO_DBG
                                        printf("Key has been deleted!\n");
#endif
                                        return DELETED;
                                }
                        }
                }
                if (j == ASSOC_WAY) {
#ifdef CUCKOO_DBG
                        printf("Key not exists!\n");
#endif
                        return AVAILIBLE;
                }
        }

        return OCCUPIED;
}

static int cuckoo_hash_put(struct hash_table *table, uint8_t *key, uint32_t *p_offset)
{
        int i, j;
        uint32_t tag[2], offset;
        struct hash_slot_cache *slot;

        tag[0] = cuckoo_hash_lsb(key, table->bucket_num);
        tag[1] = cuckoo_hash_msb(key, table->bucket_num);

#ifdef CUCKOO_DBG
        printf("put offset:%x t0:%x t1:%x\n", *p_offset, tag[0], tag[1]);
#endif

        /* Insert new key into hash buckets. */
        offset = *p_offset;
        slot = table->buckets[tag[0]];
        for (i = 0; i < ASSOC_WAY; i++) {
                if (offset == INVALID_OFFSET && slot[i].status == DELETED) {
                        slot[i].status = OCCUPIED;
                        slot[i].tag = cuckoo_hash_msb(key, table->bucket_num);
                        *p_offset = offset = slot[i].offset;
                        break;
                } else if (slot[i].status == AVAILIBLE) {
                        slot[i].status = OCCUPIED;
                        slot[i].tag = cuckoo_hash_msb(key, table->bucket_num);
                        slot[i].offset = offset;
                        break;
                }
        }

        if (i == ASSOC_WAY) {
                slot = table->buckets[tag[1]];
                for (j = 0; j < ASSOC_WAY; j++) {
                        if (offset == INVALID_OFFSET && slot[j].status == DELETED) {
                                slot[j].status = OCCUPIED;
                                slot[j].tag = cuckoo_hash_lsb(key, table->bucket_num);
                                *p_offset = offset = slot[j].offset;
                                break;
                        } else if (slot[j].status == AVAILIBLE) {
                                slot[j].status = OCCUPIED;
                                slot[j].tag = cuckoo_hash_lsb(key, table->bucket_num);
                                slot[j].offset = offset;
                                break;
                        }
                }

                if (j == ASSOC_WAY) {
                        if (cuckoo_hash_collide(table, tag, p_offset)) {
#ifdef CUCKOO_DBG
                                printf("Hash table collision!\n");
#endif
                                return -1;
                        }
                }
        }

        show_hash_slots(table);

        return 0;
}

static void cuckoo_hash_delete(struct hash_table *table, uint8_t *key)
{
        uint32_t i, j, tag[2];
        struct hash_slot_cache *slot;

        tag[0] = cuckoo_hash_lsb(key, table->bucket_num);
        tag[1] = cuckoo_hash_msb(key, table->bucket_num);

#ifdef CUCKOO_DBG
        printf("delete t0:%x t1:%x\n", tag[0], tag[1]);
#endif
        dump_sha1_key(key);

        /* Insert new key into hash buckets. */
        slot = table->buckets[tag[0]];
        for (i = 0; i < ASSOC_WAY; i++) {
                if (cuckoo_hash_msb(key, table->bucket_num) == slot[i].tag) {
                        slot[i].status = DELETED;
                        return;
                }
        }

        if (i == ASSOC_WAY) {
                slot = table->buckets[tag[1]];
                for (j = 0; j < ASSOC_WAY; j++) {
                        if (cuckoo_hash_lsb(key, table->bucket_num) == slot[j].tag) {
                                slot[j].status = DELETED;
                                return;
                        }
                }

                if (j == ASSOC_WAY) {
                        printf("Key not exists!\n");
                }
        }
}

static void cuckoo_rehash(struct hash_table *table)
{
        int i;
        struct hash_table old_table;

        /* Reallocate hash slots */
        old_table.slots = table->slots;
        old_table.slot_num = table->slot_num;
        table->slot_num *= 2;
        table->slots = calloc(table->slot_num, sizeof(struct hash_slot_cache));
        if (table->slots == NULL) {
                table->slots = old_table.slots;
                return;
        }

        /* Reallocate hash buckets associated with slots */
        old_table.buckets = table->buckets;
        old_table.bucket_num = table->bucket_num;
        table->bucket_num *= 2;
        table->buckets = malloc(table->bucket_num * sizeof(struct hash_slot_cache *));
        if (table->buckets == NULL) {
                free(table->slots);
                table->slots = old_table.slots;
                table->buckets = old_table.buckets;
                return;
        }
        for (i = 0; i < table->bucket_num; i++) {
                table->buckets[i] = &table->slots[i * ASSOC_WAY];
        }

        /* Rehash all hash slots */
        uint8_t *read_addr = nvrom_base_addr;
        uint32_t entries = log_entries;
        while (entries--) {
                uint8_t key[20];
                uint32_t offset = read_addr - nvrom_base_addr;
                for (i = 0; i < 20; i++) {
                        key[i] = flash_read(read_addr);
                        read_addr++;
                }
                /* Duplicated keys in hash table which can cause eternal
                 * hashing collision! Be careful of that!
                 */
                assert(!cuckoo_hash_put(table, key, &offset));
                if (cuckoo_hash_get(&old_table, key, NULL) == DELETED) {
                        cuckoo_hash_delete(table, key);
                }
                read_addr += DAT_LEN;
        }

       free(old_table.slots);
        free(old_table.buckets);
}

uint8_t *cuckoo_filter_get(uint8_t *key)
{
        int i;
        uint8_t *read_addr;
        static uint8_t value[DAT_LEN];

        /* Read data from the log entry on flash. */
        if (cuckoo_hash_get(&hash_table, key, &read_addr) != OCCUPIED) {
                return NULL;
        }

        for (i = 0; i < DAT_LEN; i++) {
                value[i] = flash_read(read_addr);
                read_addr++;
        }

        return value;
}

void cuckoo_filter_put(uint8_t *key, uint8_t *value)
{
        if (value != NULL) {
                int i;

                /* Important: Reject duplicated keys keeping from eternal collision */
                if (cuckoo_hash_get(&hash_table, key, NULL) == OCCUPIED) {
                        return;
                }

                /* Find new log entry offset on flash. */
                uint32_t offset = next_entry_offset();

                /* Insert into hash slots */
                if (cuckoo_hash_put(&hash_table, key, &offset) == -1) {
                        cuckoo_rehash(&hash_table);
                        cuckoo_hash_put(&hash_table, key, &offset);
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
                log_entries++;
        } else {
                /* Delete at the hash slot */
                cuckoo_hash_delete(&hash_table, key);
                /* do not do log_entries-- */
        }
}

int cuckoo_filter_init(size_t size)
{
        int i;

        /* Make whole memory space large enough(but not always predictable...) */
        nvrom_size = next_pow_of_2(size);
        nvrom_base_addr = malloc(nvrom_size + SECTOR_SIZE);
        if (nvrom_base_addr == NULL) {
                return -1;
        }
        nvrom_base_addr = force_align(nvrom_base_addr, SECTOR_SIZE);

        /* Allocate hash slots */
        hash_table.slot_num = nvrom_size / SECTOR_SIZE;
        /* Make rehashing happen */
        hash_table.slot_num /= 4;
        hash_table.slots = calloc(hash_table.slot_num, sizeof(struct hash_slot_cache));
        if (hash_table.slots == NULL) {
                return -1;
        }

        /* Allocate hash buckets associated with slots */
        hash_table.bucket_num = hash_table.slot_num / ASSOC_WAY;
        hash_table.buckets = malloc(hash_table.bucket_num * sizeof(struct hash_slot_cache *));
        if (hash_table.buckets == NULL) {
                free(hash_table.slots);
                return -1;
        }
        for (i = 0; i < hash_table.bucket_num; i++) {
                hash_table.buckets[i] = &hash_table.slots[i * ASSOC_WAY];
        }

        return 0;
}
