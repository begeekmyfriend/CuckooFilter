Cuckoo Filter
=============

A mini key-value storage filter on flash memory using cuckoo hashing.

Usage
-----

```c
cd cuckoo_filter
make
./cockoo_db input_file output_file
```

Define `CUCKOO_DBG` in cuckoo_filter.h to open debug logging.

Define `DEL_TEST` in nvrom_test.c to open deletion test.
