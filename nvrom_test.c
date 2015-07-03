#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cuckoo_db.h"
#include "mozilla-sha1/sha1.h"

#define NKEY SLOT_NUM

int main(int argc, char **argv)
{
        SHA_CTX c;
        uint8_t sha1_key[NKEY][20] = { { 0 } };
        uint8_t value[DAT_LEN], *v;
        int bytes, i, j;
        FILE *f1, *f2;

        db_init();

        if (argc < 3) {
                usage("./cuckoo_db read_file write_file");
                exit(-1);
        }

        --argc;
        ++argv;

        f1 = fopen(argv[0], "rb");
        if (f1 == NULL) {
                exit(-1);
        }

        f2 = fopen(argv[1], "wb+");
        if (f2 == NULL) {
                exit(-1);
        }

        /* Put read_file into log on flash. */
        i = 0;
        do {
                if (i >= NKEY) {
                        fprintf(stderr, "The size of the file exceeds the capacity of database.\n");
                        exit(-1);
                }
                memset(value, 0, DAT_LEN);
                bytes = fread(value, 1, DAT_LEN, f1);
                SHA1_Init(&c);
                SHA1_Update(&c, value, bytes);
                SHA1_Final(sha1_key[i], &c);
                put(sha1_key[i], value);
                i++;
        } while (bytes == DAT_LEN);

        /* Get logs on flash and write them into a new file. */
        for (j = 0; j < i; j++) {
                v = get(sha1_key[j]);
                if (v != NULL) {
                        memcpy(value, v, DAT_LEN);
                        fwrite(value, 1, DAT_LEN, f2);
                }
        }

        fclose(f1);
        fclose(f2);

        return 0;
}
