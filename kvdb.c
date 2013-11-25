/******************************************************
 * File: kvdb.c -- A mini key-value database store.
 * Date: 2013-11-25
 * Author: Leo Ma
 ******************************************************/

#include "kvdb.h"

static uint8_t *nvrom_base_addr;
static struct hash_slot_cache **hash_buckets;
static struct hash_slot_cache *hash_slots;
static uint32_t log_entries;

void inline usage(const char *s)
{
  fprintf(stderr, "usage: %s\n", s);
  exit(-1);
}

static inline uint16_t next_entry_offset()
{
  uint32_t append_addr;
  append_addr = (uint32_t)nvrom_base_addr + log_entries * sizeof(struct log_entry);
  assert(flash_align(append_addr));
  if (++log_entries * sizeof(struct log_entry) >= NVROM_SIZE)
  {
	--log_entries;
    printf("Out of flash memory!\n");
	return -1;
  }
  return (uint16_t)(append_addr - (uint32_t)nvrom_base_addr);
}

uint8_t *get(uint8_t *key)
{
  uint8_t tag[2], *read_addr;
  static uint8_t value[DAT_LEN];
  uint16_t offset;
  uint32_t i, j;
  struct hash_slot_cache *hash_slot;

  tag[0] = cuckoo_hash1(key);
  tag[1] = cuckoo_hash2(key);
  
  // Filter the key and verify if it exists.
  hash_slot = hash_buckets[tag[0]];
  for (i = 0; i < ASSOC_WAYS; i++) 
    // if (hash_slot[i].tag == tag[1])
    if (key_match_msb(key, hash_slot[i].tag))
    {
      if (hash_slot[i].status == OCCUPIED)
      {
        offset = hash_slot[i].offset;
        break;
      }
      //else
      //{
      //  printf("This entry is already deleted!\n");
      //  return NULL;
      //}
    }
  if (i == ASSOC_WAYS)
  {
    hash_slot = hash_buckets[tag[1]];
	for (j = 0; j < ASSOC_WAYS; j++)
      if (key_match_lsb(key, hash_slot[j].tag))
      {
        if (hash_slot[j].status == OCCUPIED)
		{
	      offset = hash_slot[j].offset;
		  break;
		}
	    //else
	    //{
	    //  printf("This entry is already deleted!\n");
	    //  return NULL;
	    //}
	  }
	if (j == 4)
    {
      printf("Key not exists!\n");
      return NULL;
    } 
  }

  // Verify key and read data from the log entry on flash.
  read_addr = nvrom_base_addr + offset;
  for (i = 0; i < 20; i++)
  {
    if (key[i] != flash_read(read_addr))
	{
      printf("Key not matches!\n");
	  return NULL;
	}
	read_addr++;
  }
  for (i = 0; i < DAT_LEN; i++)
  {
    value[i] = flash_read(read_addr);
	read_addr++;
  }

  return (uint8_t *)value;
}

void put(uint8_t *key, uint8_t *value)
{
  uint8_t tag[2], old_tag[2], *append_addr;
  uint16_t offset, old_offset;
  uint32_t i, j, alt_cnt;
  struct hash_slot_cache *hash_slot;

  tag[0] = cuckoo_hash1(key);
  tag[1] = cuckoo_hash2(key);
  
  // Find new log entry offset on flash.
  offset = next_entry_offset();
  if (-1 == offset)
    return;

  // Insert new key into hash buckets.
  hash_slot = hash_buckets[tag[0]];
  for (i = 0; i < ASSOC_WAYS; i++)
  {
    if (hash_slot[i].status == AVAILIBLE)
    {
      hash_slot[i].status = OCCUPIED;
	  set_tag_msb(key, hash_slot[i].tag);
      hash_slot[i].offset = offset;
      break;
    }
  }

  if (i == 4)
  {
    hash_slot = hash_buckets[tag[1]];
	for (j = 0; j < ASSOC_WAYS; j++)
	{
      if (hash_slot[j].status == AVAILIBLE)
      {
        hash_slot[j].status = OCCUPIED;
	    set_tag_lsb(key, hash_slot[i].tag);
        hash_slot[j].offset = offset;
        break;
      }
    }

	if (j == 4)
    {
      // if hash collision, kick out the old key and
	  // move it to the alternative bucket and go on inserting.
	  hash_slot = hash_buckets[tag[0]];
	  old_tag[0] = tag[0];
      old_tag[1] = hash_slot[0].tag;
      old_offset = hash_slot[0].offset;
	  set_tag_msb(key, hash_slot[0].tag);
	  hash_slot[0].offset = offset;
	  i = 0^1;
	  alt_cnt = 0;
LOOP:
	  hash_slot = hash_buckets[old_tag[i]];
	  for (j = 0; j < ASSOC_WAYS; j++)
	  {
	    if (hash_slot[j].status == AVAILIBLE)
        {
          hash_slot[j].status = OCCUPIED;
	      hash_slot[j].tag = old_tag[i^1];
	      hash_slot[j].offset = old_offset;
		  break;
		}
	  }
		
	  if (j == 4)
	  {
	    // bucket table almost full, resize hash buckets.
	    if (++alt_cnt > 128)
	    {
		  printf("This hash table almost full and needs to be resized!\n");
		  exit(-1);
	    }
	    uint8_t tmp_tag = hash_slot[0].tag;
	    uint8_t tmp_offset = hash_slot[0].offset;
	    hash_slot[0].tag = old_tag[i^1];
	    hash_slot[0].offset = old_offset;
	    old_tag[i^1] = tmp_tag;
	    old_offset = tmp_offset;
	    i ^= 1;
   	    goto LOOP;
	  }
    }
  }

  // Add new entry of key-value pair on flash.
  append_addr = nvrom_base_addr + offset;
  assert(flash_align(append_addr));
  flash_sector_erase(append_addr);
  for (i = 0; i < 20; i++)
  {
    flash_write(append_addr, key[i]);
	append_addr++;
  }
  for (i = 0; i < DAT_LEN; i++)
  {
    flash_write(append_addr, value[i]);
	append_addr++;
  }

  return;
}

void db_init()
{
  uint32_t i;

  nvrom_base_addr = (uint8_t *)malloc(NVROM_SIZE + SECTOR_SIZE);
  if (nvrom_base_addr == NULL)
	exit(-1);
  nvrom_base_addr = (uint8_t *)make_align(nvrom_base_addr, SECTOR_SIZE);

  hash_slots = (struct hash_slot_cache *)malloc(SLOT_NUM * sizeof(struct hash_slot_cache));
  if (hash_slots == NULL)
    exit(-1);

  hash_buckets = (struct hash_slot_cache **)malloc(BUCKET_NUM * sizeof(struct hash_slot_cache *));
  if (hash_slots == NULL)
    exit(-1);
  for (i = 0; i < BUCKET_NUM; i++)
    hash_buckets[i] = &hash_slots[i * ASSOC_WAYS];
}
