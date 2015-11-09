#include "yescrypt.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* Some stuff only declared in yescrypt-ref.c that we need. */
/* XXX: Having two copies of this is error prone. */
typedef struct {
	uint32_t *S;
	uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
	size_t w;
} pwxform_ctx_t;

extern void pwxform(uint32_t * B, pwxform_ctx_t * ctx);
extern void salsa20(uint32_t B[16], uint32_t rounds);

/* These are tunable */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

/* Derived values.  Not tunable on their own. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define Sbytes (3 * (1 << Swidth) * PWXsimple * 8)
#define Swords (Sbytes / sizeof(uint32_t))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define rmin ((PWXbytes + 127) / 128)

// NOTE: You MUST build the reference implementation, i.e. `make ref`.

#define MAX_COMMAND 65536

// The range of yescrypt() parameters to test. Starting at smallest value.
#define TEST_MAX_N 16
#define TEST_MAX_R 4
#define TEST_MAX_P 4
#define TEST_MAX_T 4
#define TEST_MAX_G 1
#define TEST_PASSPHRASE_LEN 11
#define TEST_SALT_LEN       11
#define TEST_PASSPHRASE "\x00pass\xFFword\x00"
#define TEST_SALT       "\x00salt\xFFNaCl\x00"

int invoke_salsa20_8(
    const char *command,
    uint8_t input[64],
    uint8_t output[64]
)
{
    int i;
    char exec_command[MAX_COMMAND];

    if (strlen(command) >= MAX_COMMAND) {
        return -1;
    }
    strcpy(exec_command, command);
    strcat(exec_command, " salsa20_8 ");

    strcat(exec_command, "'");
    for (i = 0; i < 64; i++) {
        sprintf(exec_command + strlen(exec_command), "%02x", input[i]);
    }
    strcat(exec_command, "' ");

    FILE *fp;
    size_t n;

    fp = popen(exec_command, "r");
    if (fp == NULL) {
        return -1;
    }

    n = fread(output, 1, 64, fp);
    if (n < 64) {
        return -1;
    }

    return 0;
}


int invoke_pwxform(
    const char *command,
    uint8_t input[PWXbytes],
    uint8_t sbox[Sbytes],
    uint8_t output[PWXbytes]
)
{
    int i;
    char exec_command[MAX_COMMAND];

    if (strlen(command) >= MAX_COMMAND) {
        return -1;
    }
    strcpy(exec_command, command);
    strcat(exec_command, " pwxform ");

    strcat(exec_command, "'");
    for (i = 0; i < PWXbytes; i++) {
        sprintf(exec_command + strlen(exec_command), "%02x", input[i]);
    }
    strcat(exec_command, "' ");

    strcat(exec_command, "'");
    for (i = 0; i < Sbytes; i++) {
        sprintf(exec_command + strlen(exec_command), "%02x", sbox[i]);
    }
    strcat(exec_command, "' ");

    FILE *fp;
    size_t n;

    fp = popen(exec_command, "r");
    if (fp == NULL) {
        return -1;
    }

    n = fread(output, 1, PWXbytes, fp);
    if (n < PWXbytes) {
        return -1;
    }

    return 0;
}

int invoke_yescrypt(
    const char *command,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    unsigned long N,
    unsigned long r,
    unsigned long p,
    unsigned long t,
    unsigned long g,
    yescrypt_flags_t flags,
    uint8_t *buf,
    size_t buf_len
)
{
    char exec_command[MAX_COMMAND];
    size_t i;

    exec_command[0] = 0;

    // XXX there are a bunch of integer overflow bugs in this function

    if (strlen(exec_command) + strlen(command) >= MAX_COMMAND) {
        return -1;
    }
    strcat(exec_command, command);

    if (strlen(exec_command) + strlen(" yescrypt ") >= MAX_COMMAND) {
        return -1;
    }
    strcat(exec_command, " yescrypt ");

    if (strlen(exec_command) + 1 + password_len * 2 + 1 >= MAX_COMMAND) {
        return -1;
    }
    strcat(exec_command, "'");
    for (i = 0; i < password_len; i++) {
        sprintf(exec_command + strlen(exec_command), "%02x", password[i]);
    }
    strcat(exec_command, "' ");

    if (strlen(exec_command) + 1 + salt_len * 2 + 1 >= MAX_COMMAND) {
        return -1;
    }
    strcat(exec_command, "'");
    for (i = 0; i < salt_len; i++) {
        sprintf(exec_command + strlen(exec_command), "%02x", salt[i]);
    }
    strcat(exec_command, "' ");

    if (strlen(exec_command) + 40 * 7 >= MAX_COMMAND) {
        return -1;
    }
    sprintf(exec_command + strlen(exec_command), "%lu ", N);
    sprintf(exec_command + strlen(exec_command), "%lu ", r);
    sprintf(exec_command + strlen(exec_command), "%lu ", p);
    sprintf(exec_command + strlen(exec_command), "%lu ", t);
    sprintf(exec_command + strlen(exec_command), "%lu ", g);
    sprintf(exec_command + strlen(exec_command), "%d ", flags);
    sprintf(exec_command + strlen(exec_command), "%llu ", (unsigned long long)buf_len);

    FILE *fp;
    size_t n;

    fp = popen(exec_command, "r");
    if (fp == NULL) {
        printf("popen failed.\n");
        printf("%s\n", exec_command);
        return -1;
    }

    n = fread(buf, 1, buf_len, fp);
    if (n < buf_len) {
        printf("fread failed, got %llu instead of %llu.\n", (unsigned long long)n, (unsigned long long)buf_len);
        printf("%s\n", exec_command);
        return -1;
    }

    int exit = pclose(fp);
    if (exit != 0) {
        printf("command exited with non-zero status.\n");
        return -1;
    }

    return 0;
}

int test_yescrypt(
    const char *command,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    unsigned long N,
    unsigned long r,
    unsigned long p,
    unsigned long t,
    unsigned long g,
    yescrypt_flags_t flags,
    size_t buf_len
)
{
    uint8_t *correct;
    uint8_t *computed;
    int ret, i;

    printf("yescrypt(?, ?, %lu, %lu, %lu, %lu, %lu, %d, %llu)\n", N, r, p, t, g, flags, (unsigned long long)buf_len);

    correct = malloc(buf_len);
    computed = malloc(buf_len);

    if (correct == NULL || computed == NULL) {
        printf("Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    ret = invoke_yescrypt(
        command,
        password, password_len,
        salt, salt_len,
        N, r, p, t, g, flags,
        computed, buf_len
    );

    if (ret != 0) {
        printf("Error running external program.\n");
        exit(EXIT_FAILURE);
    }

    yescrypt_local_t local;
    yescrypt_init_local(&local);
    ret = yescrypt_kdf(
            NULL, &local,
            password, password_len,
            salt, salt_len,
            N, r, p, t, g, flags,
            correct, buf_len
          );
    if (ret != 0) {
        printf("Error computing the correct value (%d, %d).\n", ret, errno);
        exit(EXIT_FAILURE);
    }

    if (memcmp(computed, correct, buf_len) != 0) {
        printf("FAILED.\n");
        printf("Expected: ");
        for (i = 0; i < buf_len; i++) {
            printf("%02x", correct[i]);
        }
        printf("\nGot:      ");
        for (i = 0; i < buf_len; i++) {
            printf("%02x", computed[i]);
        }
        printf("\n");

        free(correct);
        free(computed);
        return 1;
    }

    free(correct);
    free(computed);
    return 0;
}

int test_salsa20_8(const char *command)
{
    uint8_t B[64];
    uint8_t O[64];
    int i;

    for (i = 0; i < 64; i++) {
        B[i] = rand() & 0xFF;
    }

    invoke_salsa20_8(command, B, O);
    salsa20((uint32_t *)B, 8);

    if (memcmp(B, O, 64) != 0) {
        printf("FAILED.\n");
        printf("Expected: ");
        for (i = 0; i < 64; i++) {
            printf("%02x", B[i]);
        }
        printf("\nGot:      ");
        for (i = 0; i < 64; i++) {
            printf("%02x", O[i]);
        }
        printf("\n");
        return 1;
    }

    return 0;
}

int test_pwxform(const char *command)
{
    uint8_t B[PWXbytes];
    uint8_t O[PWXbytes];
    uint8_t S[Sbytes];
    int i;

    for (i = 0; i < PWXbytes; i++) {
        B[i] = rand() & 0xFF;
    }

    for (i = 0; i < Sbytes; i++) {
        S[i] = rand() & 0xFF;
    }

    invoke_pwxform(command, B, S, O);

    pwxform_ctx_t ctx[1];

    /* Copied from yescrypt-ref.c, used to be in pwxform_init() in 0.8. */
    ctx->S = (uint32_t *)S;
    ctx->S2 = (uint32_t (*)[2])ctx->S;
    ctx->S1 = ctx->S2 + (1 << Swidth) * PWXsimple;
    ctx->S0 = ctx->S1 + (1 << Swidth) * PWXsimple;

    pwxform((uint32_t *)B, ctx);

    if (memcmp(B, O, PWXbytes) != 0) {
        printf("FAILED.\n");
        printf("Expected: ");
        for (i = 0; i < PWXbytes; i++) {
            printf("%02x", B[i]);
        }
        printf("\nGot:      ");
        for (i = 0; i < PWXbytes; i++) {
            printf("%02x", O[i]);
        }
        printf("\n");
        return 1;
    }

    return 0;
}

typedef struct YescryptTestCase {
    const char *passphrase;
    size_t passphrase_len;
    const char *salt;
    size_t salt_len;
    int N;
    int r;
    int p;
    int t;
    int g;
    int dkLen;
    // We automatically test all flag settings compatible with the other
    // parameters.
} testcase_t;

testcase_t custom_cases[] = {
    // Passphrase                           Salt                      N  r  p  t  g  dkLen
    // ------------------------------------------------------------------------------------
    // r=8
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 8, 1, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 4, 8, 1, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 8, 2, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 8, 1, 1, 0, 32 },
    // r=16
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 16, 1, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 4, 16, 1, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 16, 2, 0, 0, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 16, 1, 1, 0, 32 },
    // empty passphrase
    { "",              0,                   TEST_SALT, TEST_SALT_LEN, 4, 4, 2, 0, 0, 32 },
    // empty salt
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, "",        0,             4, 4, 2, 0, 0, 32 },
    // big g
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 4, 2, 0, 1, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 4, 2, 0, 2, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 4, 2, 0, 3, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 2, 4, 2, 0, 4, 32 },
    { TEST_PASSPHRASE, TEST_PASSPHRASE_LEN, TEST_SALT, TEST_SALT_LEN, 4, 4, 2, 1, 2, 32 },
};

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: ./tester 'command prefix'\n");
        exit(EXIT_FAILURE);
    }

    int fail = 0;
    int i;

    unsigned long N, r, p, t, g;

    printf("Testing salsa20/8.\n");
    for (i = 0; i < 100; i++) {
        fail |= test_salsa20_8(argv[1]);
    }

    printf("Testing pwxform.\n");
    for (i = 0; i < 100; i++) {
        fail |= test_pwxform(argv[1]);
    }

    //// Test the YESCRYPT_PREHASH case.
    //fail |= test_yescrypt(
    //    argv[1],
    //    (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
    //    (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
    //    0x100, 0x200000 / 0x100, 1, 1, 0, YESCRYPT_RW,
    //    16
    //);

    for (i = 0; i < sizeof(custom_cases) / sizeof(testcase_t); i++) {
        if (custom_cases[i].t == 0) {
            fail |= test_yescrypt(
                argv[1],
                (const uint8_t *)custom_cases[i].passphrase, custom_cases[i].passphrase_len,
                (const uint8_t *)custom_cases[i].salt, custom_cases[i].salt_len,
                custom_cases[i].N, custom_cases[i].r, custom_cases[i].p, custom_cases[i].t,
                custom_cases[i].g, 0, custom_cases[i].dkLen
            );
        }

        if (custom_cases[i].N/custom_cases[i].p > 1) {
            fail |= test_yescrypt(
                argv[1],
                (const uint8_t *)custom_cases[i].passphrase, custom_cases[i].passphrase_len,
                (const uint8_t *)custom_cases[i].salt, custom_cases[i].salt_len,
                custom_cases[i].N, custom_cases[i].r, custom_cases[i].p, custom_cases[i].t,
                custom_cases[i].g, YESCRYPT_RW, custom_cases[i].dkLen
            );
        }
        fail |= test_yescrypt(
            argv[1],
            (const uint8_t *)custom_cases[i].passphrase, custom_cases[i].passphrase_len,
            (const uint8_t *)custom_cases[i].salt, custom_cases[i].salt_len,
            custom_cases[i].N, custom_cases[i].r, custom_cases[i].p, custom_cases[i].t,
            custom_cases[i].g, YESCRYPT_WORM, custom_cases[i].dkLen
        );
    }

    for (N = 2; N <= TEST_MAX_N; N = N << 1) {
        for (r = 1; r <= TEST_MAX_R; r++) {
            for (p = 1; p <= TEST_MAX_P; p++) {
                for (t = 0; t <= TEST_MAX_T; t++) {
                    for (g = 0; g <= TEST_MAX_G; g++) {
                        // >= 32 byte output.
                        if (t == 0) {
                            fail |= test_yescrypt(
                                argv[1],
                                (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                                (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                                N, r, p, t, g, 0,
                                64
                            );
                        }
                        if (N/p > 1) {
                            fail |= test_yescrypt(
                                argv[1],
                                (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                                (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                                N, r, p, t, g, YESCRYPT_RW,
                                64
                            );
                        }
                        fail |= test_yescrypt(
                            argv[1],
                            (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                            (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                            N, r, p, t, g, YESCRYPT_WORM,
                            64
                        );

                        // < 32 byte output.
                        if (t == 0) {
                            fail |= test_yescrypt(
                                argv[1],
                                (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                                (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                                N, r, p, t, g, 0,
                                16
                            );
                        }
                        if (N/p > 1) {
                            fail |= test_yescrypt(
                                argv[1],
                                (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                                (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                                N, r, p, t, g, YESCRYPT_RW,
                                16
                            );
                        }
                        fail |= test_yescrypt(
                            argv[1],
                            (const uint8_t *)TEST_PASSPHRASE, TEST_PASSPHRASE_LEN,
                            (const uint8_t *)TEST_SALT, TEST_SALT_LEN,
                            N, r, p, t, g, YESCRYPT_WORM,
                            16
                        );
                    }
                }
            }
        }
    }

    if (fail) {
        printf("Some tests failed!\n");
        exit(EXIT_FAILURE);
    } else {
        printf("All tests pass.\n");
    }

    exit(EXIT_SUCCESS);
}
