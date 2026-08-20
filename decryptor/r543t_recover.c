#define _CRT_SECURE_NO_WARNINGS /*to avoid MSVC compilation problem*/
/*
 * r543t / ok75 ransomware recovery tool
 *
 * Defensive recovery utility for the AutoIt ransomware lineage analysed in the
 * accompanying research.  The tool reproduces the ransomware's accidental
 * key derivation:
 *
 *     LE32(HCRYPTKEY) -> MD5 -> CryptoAPI AES-256 MD5 expansion
 *
 * It can:
 *   - brute-force the 32-bit HCRYPTKEY space using built-in file signatures;
 *   - use a manually supplied known plaintext header;
 *   - decrypt a single file after recovering or supplying a handle;
 *   - recursively recover .r543t/.ok75/.ok45 trees while preserving paths;
 *   - discover multiple handles when several ransomware executions are mixed;
 *   - read handles directly from sslog.txt;
 *   - recognise ransomware-suffixed files that were never encrypted.
 *
 * The program has no third-party runtime or cryptographic dependency. MD5 and
 * AES-256 decryption are implemented locally. Input files are never modified.
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#define AES_BLOCK_SIZE       16U
#define PARTIAL_PLAIN_CHUNK  10000U
#define PARTIAL_CIPHER_CHUNK 10016U
#define PARTIAL_TRAILER_SIZE 32U
#define MAX_THREADS          64U
#define MAX_MAGIC_BYTES      32U
#define MAX_MAGIC_PATTERNS   12U
#define PROBE_PREFIX_BYTES   64U
#define MAX_RECOVERY_KEYS    64U
#define PATH_BUFFER_SIZE     4096U
#define PROGRESS_BATCH       16384U

/* ------------------------------------------------------------------------- */
/* Small platform abstraction                                                */
/* ------------------------------------------------------------------------- */

#ifdef _WIN32

typedef volatile LONG atomic_u32;
typedef volatile LONG64 atomic_u64;

typedef HANDLE thread_handle;

typedef DWORD(WINAPI *windows_thread_proc)(LPVOID);

static uint32_t atomic_load_u32(const atomic_u32 *value)
{
    return (uint32_t)InterlockedCompareExchange((volatile LONG *)value, 0, 0);
}

static uint64_t atomic_load_u64(const atomic_u64 *value)
{
    return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)value, 0, 0);
}

static int atomic_try_set(atomic_u32 *value)
{
    return InterlockedCompareExchange(value, 1, 0) == 0;
}

static void atomic_add_u64(atomic_u64 *value, uint64_t amount)
{
    InterlockedAdd64(value, (LONG64)amount);
}

static void atomic_dec_u32(atomic_u32 *value)
{
    InterlockedDecrement(value);
}

static uint64_t monotonic_ms(void)
{
    return GetTickCount64();
}

static void sleep_ms(uint32_t milliseconds)
{
    Sleep(milliseconds);
}

static uint32_t logical_cpu_count(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors ? info.dwNumberOfProcessors : 1U;
}

static int seek_file(FILE *file, uint64_t offset)
{
    return _fseeki64(file, (int64_t)offset, SEEK_SET) == 0;
}

static int seek_file_end(FILE *file)
{
    return _fseeki64(file, 0, SEEK_END) == 0;
}

static int64_t tell_file(FILE *file)
{
    return _ftelli64(file);
}

#else

typedef _Atomic uint32_t atomic_u32;
typedef _Atomic uint64_t atomic_u64;

typedef pthread_t thread_handle;

static uint32_t atomic_load_u32(const atomic_u32 *value)
{
    return atomic_load_explicit(value, memory_order_relaxed);
}

static uint64_t atomic_load_u64(const atomic_u64 *value)
{
    return atomic_load_explicit(value, memory_order_relaxed);
}

static int atomic_try_set(atomic_u32 *value)
{
    uint32_t expected = 0;
    return atomic_compare_exchange_strong_explicit(
        value,
        &expected,
        1,
        memory_order_acq_rel,
        memory_order_relaxed);
}

static void atomic_add_u64(atomic_u64 *value, uint64_t amount)
{
    atomic_fetch_add_explicit(value, amount, memory_order_relaxed);
}

static void atomic_dec_u32(atomic_u32 *value)
{
    atomic_fetch_sub_explicit(value, 1, memory_order_release);
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void sleep_ms(uint32_t milliseconds)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(milliseconds / 1000U);
    ts.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
    nanosleep(&ts, NULL);
}

static uint32_t logical_cpu_count(void)
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? (uint32_t)count : 1U;
}

static int seek_file(FILE *file, uint64_t offset)
{
    return fseeko(file, (off_t)offset, SEEK_SET) == 0;
}

static int seek_file_end(FILE *file)
{
    return fseeko(file, 0, SEEK_END) == 0;
}

static int64_t tell_file(FILE *file)
{
    return (int64_t)ftello(file);
}

#endif

/* ------------------------------------------------------------------------- */
/* Endian helpers                                                            */
/* ------------------------------------------------------------------------- */

static uint32_t rotate_left32(uint32_t value, uint32_t count)
{
    return (value << count) | (value >> (32U - count));
}

static uint32_t load_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16)
        | ((uint32_t)bytes[3] << 24);
}

static void store_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

/* ------------------------------------------------------------------------- */
/* MD5 specialised for the ransomware KDF                                   */
/* ------------------------------------------------------------------------- */

static const uint32_t md5_k[64] = {
0xd76aa478U,0xe8c7b756U,0x242070dbU,0xc1bdceeeU,0xf57c0fafU,0x4787c62aU,0xa8304613U,0xfd469501U,
0x698098d8U,0x8b44f7afU,0xffff5bb1U,0x895cd7beU,0x6b901122U,0xfd987193U,0xa679438eU,0x49b40821U,
0xf61e2562U,0xc040b340U,0x265e5a51U,0xe9b6c7aaU,0xd62f105dU,0x02441453U,0xd8a1e681U,0xe7d3fbc8U,
0x21e1cde6U,0xc33707d6U,0xf4d50d87U,0x455a14edU,0xa9e3e905U,0xfcefa3f8U,0x676f02d9U,0x8d2a4c8aU,
0xfffa3942U,0x8771f681U,0x6d9d6122U,0xfde5380cU,0xa4beea44U,0x4bdecfa9U,0xf6bb4b60U,0xbebfbc70U,
0x289b7ec6U,0xeaa127faU,0xd4ef3085U,0x04881d05U,0xd9d4d039U,0xe6db99e5U,0x1fa27cf8U,0xc4ac5665U,
0xf4292244U,0x432aff97U,0xab9423a7U,0xfc93a039U,0x655b59c3U,0x8f0ccc92U,0xffeff47dU,0x85845dd1U,
0x6fa87e4fU,0xfe2ce6e0U,0xa3014314U,0x4e0811a1U,0xf7537e82U,0xbd3af235U,0x2ad7d2bbU,0xeb86d391U};

static const uint8_t md5_s[64] = {
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

static void md5_init_state(uint32_t state[4])
{
    state[0] = 0x67452301U;
    state[1] = 0xefcdab89U;
    state[2] = 0x98badcfeU;
    state[3] = 0x10325476U;
}

static void md5_compress_block(uint32_t state[4], const uint32_t words[16])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t f;
        uint32_t g;

        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5U * i + 1U) & 15U;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3U * i + 5U) & 15U;
        } else {
            f = c ^ (b | (~d));
            g = (7U * i) & 15U;
        }

        uint32_t old_d = d;
        d = c;
        c = b;
        b += rotate_left32(a + f + md5_k[i] + words[g], md5_s[i]);
        a = old_d;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/*
 * MD5 of exactly four bytes containing the HCRYPTKEY in little-endian order.
 * This is the hot path of the brute-force loop, so it is specialised instead
 * of using a generic MD5 implementation.
 */
static void md5_handle_le32(uint32_t handle, uint8_t digest[16])
{
    uint32_t state[4];
    uint32_t words[16] = {0};

    md5_init_state(state);
    words[0] = handle;
    words[1] = 0x00000080U;
    words[14] = 32U; /* message length in bits */
    md5_compress_block(state, words);

    for (uint32_t i = 0; i < 4; i++) {
        store_u32_le(digest + 4U * i, state[i]);
    }
}

/*
 * Compute MD5 over the 64-byte CryptoAPI expansion buffer. The first sixteen
 * bytes are digest XOR pad, and the remaining bytes are pad. Because the input
 * is exactly 64 bytes, MD5 needs a second padding block.
 */
static void md5_cryptoapi_expansion(
    const uint8_t digest[16],
    uint8_t pad,
    uint8_t output[16])
{
    uint32_t state[4];
    uint32_t words[16];
    uint32_t repeated_pad = (uint32_t)pad
        | ((uint32_t)pad << 8)
        | ((uint32_t)pad << 16)
        | ((uint32_t)pad << 24);

    md5_init_state(state);

    for (uint32_t i = 0; i < 4; i++) {
        words[i] = load_u32_le(digest + 4U * i) ^ repeated_pad;
    }
    for (uint32_t i = 4; i < 16; i++) {
        words[i] = repeated_pad;
    }
    md5_compress_block(state, words);

    memset(words, 0, sizeof(words));
    words[0] = 0x00000080U;
    words[14] = 512U; /* 64 bytes in bits */
    md5_compress_block(state, words);

    for (uint32_t i = 0; i < 4; i++) {
        store_u32_le(output + 4U * i, state[i]);
    }
}

static void derive_file_key(uint32_t handle, uint8_t key[32])
{
    uint8_t digest[16];

    md5_handle_le32(handle, digest);
    md5_cryptoapi_expansion(digest, 0x36, key);
    md5_cryptoapi_expansion(digest, 0x5c, key + 16);
}

/* ------------------------------------------------------------------------- */
/* AES-256 decryption                                                        */
/* ------------------------------------------------------------------------- */

static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const uint8_t rsbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

static const uint8_t rcon[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

static void aes256_expand_key(const uint8_t key[32], uint8_t round_keys[240])
{
    uint32_t bytes_generated = 32;
    uint32_t rcon_index = 1;
    uint8_t temp[4];

    memcpy(round_keys, key, 32);

    while (bytes_generated < 240) {
        memcpy(temp, round_keys + bytes_generated - 4, 4);

        if ((bytes_generated % 32U) == 0) {
            uint8_t first = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rcon_index++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[first];
        } else if ((bytes_generated % 32U) == 16U) {
            for (uint32_t i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
        }

        for (uint32_t i = 0; i < 4; i++) {
            round_keys[bytes_generated] =
                round_keys[bytes_generated - 32] ^ temp[i];
            bytes_generated++;
        }
    }
}

static uint8_t gf_multiply(uint8_t a, uint8_t b)
{
    uint8_t result = 0;

    for (uint32_t i = 0; i < 8; i++) {
        if (b & 1U) {
            result ^= a;
        }

        uint8_t high_bit = a & 0x80U;
        a <<= 1;
        if (high_bit) {
            a ^= 0x1bU;
        }
        b >>= 1;
    }

    return result;
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *round_key)
{
    for (uint32_t i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void aes_inverse_sub_bytes(uint8_t state[16])
{
    for (uint32_t i = 0; i < 16; i++) {
        state[i] = rsbox[state[i]];
    }
}

static void aes_inverse_shift_rows(uint8_t state[16])
{
    uint8_t temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static void aes_inverse_mix_columns(uint8_t state[16])
{
    for (uint32_t column = 0; column < 4; column++) {
        uint32_t i = 4U * column;
        uint8_t a = state[i];
        uint8_t b = state[i + 1];
        uint8_t c = state[i + 2];
        uint8_t d = state[i + 3];

        state[i] = gf_multiply(a, 14) ^ gf_multiply(b, 11)
            ^ gf_multiply(c, 13) ^ gf_multiply(d, 9);
        state[i + 1] = gf_multiply(a, 9) ^ gf_multiply(b, 14)
            ^ gf_multiply(c, 11) ^ gf_multiply(d, 13);
        state[i + 2] = gf_multiply(a, 13) ^ gf_multiply(b, 9)
            ^ gf_multiply(c, 14) ^ gf_multiply(d, 11);
        state[i + 3] = gf_multiply(a, 11) ^ gf_multiply(b, 13)
            ^ gf_multiply(c, 9) ^ gf_multiply(d, 14);
    }
}

static void aes256_decrypt_block(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t round_keys[240])
{
    uint8_t state[16];
    memcpy(state, input, 16);

    aes_add_round_key(state, round_keys + 224);

    for (int round = 13; round >= 1; round--) {
        aes_inverse_shift_rows(state);
        aes_inverse_sub_bytes(state);
        aes_add_round_key(state, round_keys + 16 * round);
        aes_inverse_mix_columns(state);
    }

    aes_inverse_shift_rows(state);
    aes_inverse_sub_bytes(state);
    aes_add_round_key(state, round_keys);

    memcpy(output, state, 16);
}

/* ------------------------------------------------------------------------- */
/* File formats and ransomware layouts                                       */
/* ------------------------------------------------------------------------- */

enum layout_kind {
    LAYOUT_UNKNOWN = 0,
    LAYOUT_PARTIAL_10K,
    LAYOUT_WHOLE_FILE,
    LAYOUT_R543T_TINY
};

struct magic_pattern {
    uint8_t bytes[MAX_MAGIC_BYTES];
    uint32_t length;
    uint32_t offset;
    const char *label;
};

struct probe_info {
    enum layout_kind layout;
    uint64_t file_size;

    uint8_t encrypted_prefix[PROBE_PREFIX_BYTES];
    uint32_t encrypted_prefix_length;

    uint8_t tail_previous[16];
    uint8_t tail_last[16];
    int has_tail;

    uint8_t legacy_main_previous[16];
    uint8_t legacy_main_last[16];
    uint8_t legacy_extra_block[16];
    int has_legacy_tail;
};

struct options {
    uint32_t threads;
    uint32_t step;
    uint64_t start;
    uint64_t end;

    int verify_padding;
    int force;
    int multi_key;
    int trust_key;
    int dry_run;

    const char *manual_magic;
    uint32_t manual_magic_offset;
    const char *forced_type;
};

struct file_entry {
    char *full_path;
    char *relative_path;
    char original_extension[32];
    char ransomware_suffix[8];
    uint64_t size;

    int resolved;
    int plaintext_renamed;
    int tried_as_probe;
    uint32_t handle;
    char status[32];
};

struct file_vector {
    struct file_entry *items;
    size_t count;
    size_t capacity;
};

static const char *layout_name(enum layout_kind layout)
{
    switch (layout) {
    case LAYOUT_PARTIAL_10K:
        return "partial-10k";
    case LAYOUT_WHOLE_FILE:
        return "whole-file";
    case LAYOUT_R543T_TINY:
        return "r543t-tiny";
    default:
        return "unsupported";
    }
}

static int ascii_lower(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int string_iequals(const char *left, const char *right)
{
    while (*left && *right) {
        if (ascii_lower((unsigned char)*left)
            != ascii_lower((unsigned char)*right)) {
            return 0;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static int string_iends_with(const char *text, const char *suffix)
{
    size_t text_length = strlen(text);
    size_t suffix_length = strlen(suffix);

    if (suffix_length > text_length) {
        return 0;
    }

    text += text_length - suffix_length;
    for (size_t i = 0; i < suffix_length; i++) {
        if (ascii_lower((unsigned char)text[i])
            != ascii_lower((unsigned char)suffix[i])) {
            return 0;
        }
    }
    return 1;
}

static void copy_string(char *destination, size_t capacity, const char *source)
{
    if (capacity == 0) {
        return;
    }

    size_t length = strlen(source);
    if (length >= capacity) {
        length = capacity - 1;
    }

    memcpy(destination, source, length);
    destination[length] = '\0';
}

static char *duplicate_string(const char *source)
{
    size_t length = strlen(source) + 1;
    char *copy = (char *)malloc(length);
    if (copy) {
        memcpy(copy, source, length);
    }
    return copy;
}

static int join_path(
    char *destination,
    size_t capacity,
    const char *left,
    const char *right)
{
#ifdef _WIN32
    const char separator = '\\';
#else
    const char separator = '/';
#endif

    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    int needs_separator = left_length > 0
        && left[left_length - 1] != '/'
        && left[left_length - 1] != '\\';

    size_t required = left_length + right_length + (needs_separator ? 1U : 0U) + 1U;
    if (required > capacity) {
        return 0;
    }

    memcpy(destination, left, left_length);
    size_t offset = left_length;

    if (needs_separator) {
        destination[offset++] = separator;
    }

    memcpy(destination + offset, right, right_length);
    destination[offset + right_length] = '\0';
    return 1;
}

static const char *base_name(const char *path)
{
    const char *last = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            last = p + 1;
        }
    }
    return last;
}

static const char *ransomware_suffix(const char *path)
{
    if (string_iends_with(path, ".ok75")) {
        return ".ok75";
    }
    if (string_iends_with(path, ".r543t")) {
        return ".r543t";
    }
    if (string_iends_with(path, ".ok45")) {
        return ".ok45";
    }
    return NULL;
}

static void original_extension(
    const char *path,
    const char *suffix,
    char output[32])
{
    const char *name = base_name(path);
    size_t clean_length = strlen(name) - strlen(suffix);
    const char *last_dot = NULL;

    for (size_t i = 0; i < clean_length; i++) {
        if (name[i] == '.') {
            last_dot = name + i;
        }
    }

    if (!last_dot) {
        output[0] = '\0';
        return;
    }

    size_t dot_offset = (size_t)(last_dot - name);
    size_t extension_length = clean_length - dot_offset;
    if (extension_length >= 32) {
        extension_length = 31;
    }

    for (size_t i = 0; i < extension_length; i++) {
        output[i] = (char)ascii_lower((unsigned char)last_dot[i]);
    }
    output[extension_length] = '\0';
}

static enum layout_kind detect_layout(const char *suffix, uint64_t encrypted_size)
{
    if (string_iequals(suffix, ".r543t")) {
        if (encrypted_size >= 20064ULL) {
            return LAYOUT_PARTIAL_10K;
        }

        /*
         * Observed legacy malformed small-file path:
         * AES-CBC-PKCS7(file) || AES-CBC-PKCS7(empty).
         */
        if (encrypted_size >= 32ULL
            && encrypted_size <= 10016ULL
            && encrypted_size % AES_BLOCK_SIZE == 0) {
            return LAYOUT_R543T_TINY;
        }
        return LAYOUT_UNKNOWN;
    }

    if (string_iequals(suffix, ".ok75") || string_iequals(suffix, ".ok45")) {
        /* 2025 sample falls back to whole-file encryption below 20,036 bytes. */
        if (encrypted_size >= 16ULL
            && encrypted_size <= 20048ULL
            && encrypted_size % AES_BLOCK_SIZE == 0) {
            return LAYOUT_WHOLE_FILE;
        }

        /* Original >= 20,036 bytes, then partial layout adds 32 bytes. */
        if (encrypted_size >= 20068ULL) {
            return LAYOUT_PARTIAL_10K;
        }
        return LAYOUT_UNKNOWN;
    }

    return LAYOUT_UNKNOWN;
}

/* ------------------------------------------------------------------------- */
/* Built-in known plaintext signatures                                       */
/* ------------------------------------------------------------------------- */

static int parse_hex(const char *text, uint8_t *output, uint32_t *output_length)
{
    uint32_t length = 0;
    int high_nibble = -1;

    for (; *text; text++) {
        int value;
        char c = *text;

        if (c == ' ' || c == ':' || c == '-' || c == '\t') {
            continue;
        }

        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        } else {
            return 0;
        }

        if (high_nibble < 0) {
            high_nibble = value;
        } else {
            if (length >= MAX_MAGIC_BYTES) {
                return 0;
            }
            output[length++] = (uint8_t)((high_nibble << 4) | value);
            high_nibble = -1;
        }
    }

    if (high_nibble >= 0 || length == 0) {
        return 0;
    }

    *output_length = length;
    return 1;
}

static int add_magic_pattern(
    struct magic_pattern patterns[MAX_MAGIC_PATTERNS],
    uint32_t *count,
    uint32_t offset,
    const char *hex,
    const char *label)
{
    if (*count >= MAX_MAGIC_PATTERNS) {
        return 0;
    }

    uint32_t length = 0;
    if (!parse_hex(hex, patterns[*count].bytes, &length)) {
        return 0;
    }

    patterns[*count].length = length;
    patterns[*count].offset = offset;
    patterns[*count].label = label;
    (*count)++;
    return 1;
}

static int is_text_extension(const char *extension)
{
    static const char *extensions[] = {
        ".txt", ".log", ".ini", ".inf", ".cfg", ".conf", ".csv", ".tsv",
        ".xml", ".json", ".md", ".yaml", ".yml", ".html", ".htm", ".css",
        ".js", ".ps1", ".bat", ".cmd", ".vbs", ".reg", ".sql", ".rtf",
        ".properties", ".config"
    };

    for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (string_iequals(extension, extensions[i])) {
            return 1;
        }
    }
    return 0;
}

static int load_type_patterns(
    const char *type,
    struct magic_pattern patterns[MAX_MAGIC_PATTERNS],
    uint32_t *count,
    int *text_mode,
    const char **display_name)
{
    *count = 0;
    *text_mode = 0;
    *display_name = type;

    if (is_text_extension(type) || string_iequals(type, "text")) {
        *text_mode = 1;
        *display_name = "text";
        return 1;
    }

#define TYPE_IS(a, b) (string_iequals(type, (a)) || string_iequals(type, (b)))

    if (TYPE_IS(".jpg", "jpg") || TYPE_IS(".jpeg", "jpeg")) {
        *display_name = "JPEG";
        add_magic_pattern(patterns, count, 0, "FFD8FFE0", "JPEG/JFIF");
        add_magic_pattern(patterns, count, 0, "FFD8FFE1", "JPEG/EXIF");
        add_magic_pattern(patterns, count, 0, "FFD8FFDB", "JPEG/DQT");
        add_magic_pattern(patterns, count, 0, "FFD8FFE2", "JPEG/ICC");
        add_magic_pattern(patterns, count, 0, "FFD8FFEE", "JPEG/Adobe");
        add_magic_pattern(patterns, count, 0, "FFD8FFE8", "JPEG/SPIFF");
        return 1;
    }
    if (TYPE_IS(".png", "png")) {
        *display_name = "PNG";
        return add_magic_pattern(patterns, count, 0, "89504E470D0A1A0A", "PNG");
    }
    if (TYPE_IS(".pdf", "pdf")) {
        *display_name = "PDF";
        return add_magic_pattern(patterns, count, 0, "255044462D", "PDF");
    }
    if (TYPE_IS(".gif", "gif")) {
        *display_name = "GIF";
        add_magic_pattern(patterns, count, 0, "474946383761", "GIF87a");
        add_magic_pattern(patterns, count, 0, "474946383961", "GIF89a");
        return 1;
    }
    if (TYPE_IS(".bmp", "bmp")) {
        *display_name = "BMP";
        return add_magic_pattern(patterns, count, 0, "424D", "BMP");
    }

    if (TYPE_IS(".zip", "zip")
        || string_iequals(type, ".docx")
        || string_iequals(type, ".xlsx")
        || string_iequals(type, ".pptx")
        || string_iequals(type, ".jar")
        || string_iequals(type, ".apk")) {
        *display_name = "ZIP/OOXML";
        add_magic_pattern(patterns, count, 0, "504B0304", "ZIP local header");
        add_magic_pattern(patterns, count, 0, "504B0506", "ZIP empty archive");
        add_magic_pattern(patterns, count, 0, "504B0708", "ZIP spanning");
        return 1;
    }

    if (string_iequals(type, ".doc")
        || string_iequals(type, ".xls")
        || string_iequals(type, ".ppt")
        || string_iequals(type, "ole")) {
        *display_name = "OLE Compound File";
        return add_magic_pattern(
            patterns, count, 0, "D0CF11E0A1B11AE1", "OLE Compound File");
    }

    if (TYPE_IS(".exe", "exe")
        || string_iequals(type, ".dll")
        || string_iequals(type, ".sys")
        || string_iequals(type, ".scr")
        || string_iequals(type, ".cpl")
        || string_iequals(type, "pe")) {
        *display_name = "PE";
        return add_magic_pattern(patterns, count, 0, "4D5A", "MZ");
    }

    if (TYPE_IS(".7z", "7z")) {
        *display_name = "7-Zip";
        return add_magic_pattern(patterns, count, 0, "377ABCAF271C", "7-Zip");
    }
    if (TYPE_IS(".rar", "rar")) {
        *display_name = "RAR";
        add_magic_pattern(patterns, count, 0, "526172211A0700", "RAR4");
        add_magic_pattern(patterns, count, 0, "526172211A070100", "RAR5");
        return 1;
    }
    if (TYPE_IS(".gz", "gzip")) {
        *display_name = "gzip";
        return add_magic_pattern(patterns, count, 0, "1F8B08", "gzip");
    }
    if (TYPE_IS(".bz2", "bz2")) {
        *display_name = "bzip2";
        return add_magic_pattern(patterns, count, 0, "425A68", "bzip2");
    }
    if (TYPE_IS(".sqlite", "sqlite") || string_iequals(type, ".sqlite3")) {
        *display_name = "SQLite";
        return add_magic_pattern(
            patterns, count, 0, "53514C69746520666F726D6174203300", "SQLite");
    }
    if (TYPE_IS(".elf", "elf")) {
        *display_name = "ELF";
        return add_magic_pattern(patterns, count, 0, "7F454C46", "ELF");
    }
    if (TYPE_IS(".lnk", "lnk")) {
        *display_name = "Windows LNK";
        return add_magic_pattern(
            patterns, count, 0, "4C0000000114020000000000C0000000", "LNK");
    }
    if (TYPE_IS(".evtx", "evtx")) {
        *display_name = "EVTX";
        return add_magic_pattern(patterns, count, 0, "456C6646696C6500", "EVTX");
    }
    if (TYPE_IS(".vhdx", "vhdx")) {
        *display_name = "VHDX";
        return add_magic_pattern(patterns, count, 0, "7668647866696C65", "VHDX");
    }
    if (TYPE_IS(".qcow2", "qcow2")) {
        *display_name = "QCOW2";
        return add_magic_pattern(patterns, count, 0, "514649FB", "QCOW2");
    }
    if (TYPE_IS(".tif", "tif") || TYPE_IS(".tiff", "tiff")) {
        *display_name = "TIFF";
        add_magic_pattern(patterns, count, 0, "49492A00", "TIFF little-endian");
        add_magic_pattern(patterns, count, 0, "4D4D002A", "TIFF big-endian");
        return 1;
    }
    if (TYPE_IS(".mp4", "mp4") || TYPE_IS(".mov", "mov")) {
        *display_name = "ISO BMFF";
        return add_magic_pattern(patterns, count, 4, "66747970", "ftyp");
    }
    if (TYPE_IS(".pcap", "pcap")) {
        *display_name = "PCAP";
        add_magic_pattern(patterns, count, 0, "D4C3B2A1", "PCAP LE");
        add_magic_pattern(patterns, count, 0, "A1B2C3D4", "PCAP BE");
        add_magic_pattern(patterns, count, 0, "4D3CB2A1", "PCAP ns LE");
        add_magic_pattern(patterns, count, 0, "A1B23C4D", "PCAP ns BE");
        return 1;
    }
    if (TYPE_IS(".pcapng", "pcapng")) {
        *display_name = "PCAPNG";
        return add_magic_pattern(patterns, count, 0, "0A0D0D0A", "PCAPNG");
    }

#undef TYPE_IS
    return 0;
}

static int magic_patterns_match(
    const uint8_t *plaintext,
    uint32_t plaintext_length,
    const struct magic_pattern *patterns,
    uint32_t pattern_count)
{
    for (uint32_t i = 0; i < pattern_count; i++) {
        const struct magic_pattern *pattern = &patterns[i];
        if (pattern->offset + pattern->length <= plaintext_length
            && memcmp(
                plaintext + pattern->offset,
                pattern->bytes,
                pattern->length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int looks_like_text(const uint8_t *data, uint32_t length)
{
    uint32_t check_length = length > 32U ? 32U : length;
    uint32_t printable = 0;
    uint32_t high_bytes = 0;

    if (check_length < 16U) {
        return 0;
    }

    for (uint32_t i = 0; i < check_length; i++) {
        uint8_t c = data[i];

        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e)) {
            printable++;
        } else if (c >= 0x80) {
            high_bytes++;
        } else {
            return 0;
        }
    }

    if (check_length >= 32U) {
        return printable >= 30U && printable + high_bytes == check_length;
    }

    return printable + high_bytes == check_length
        && printable * 100U >= check_length * 90U;
}

/* ------------------------------------------------------------------------- */
/* Probe preparation and candidate validation                                */
/* ------------------------------------------------------------------------- */

static int file_size(FILE *file, uint64_t *size)
{
    if (!seek_file_end(file)) {
        return 0;
    }

    int64_t result = tell_file(file);
    if (result < 0) {
        return 0;
    }

    *size = (uint64_t)result;
    return 1;
}

static int read_at(FILE *file, uint64_t offset, void *buffer, size_t length)
{
    return seek_file(file, offset) && fread(buffer, 1, length, file) == length;
}

static int prepare_probe(
    const char *path,
    const char *suffix,
    struct probe_info *probe)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        return 0;
    }

    memset(probe, 0, sizeof(*probe));

    if (!file_size(file, &probe->file_size)) {
        fclose(file);
        return 0;
    }

    probe->layout = detect_layout(suffix, probe->file_size);
    if (probe->layout == LAYOUT_UNKNOWN) {
        fclose(file);
        return 0;
    }

    uint64_t main_ciphertext_size = probe->file_size;
    if (probe->layout == LAYOUT_R543T_TINY) {
        main_ciphertext_size -= 16ULL;
    }

    uint32_t prefix_length =
        (uint32_t)(main_ciphertext_size < PROBE_PREFIX_BYTES
            ? main_ciphertext_size
            : PROBE_PREFIX_BYTES);
    prefix_length -= prefix_length % AES_BLOCK_SIZE;

    if (prefix_length < AES_BLOCK_SIZE) {
        fclose(file);
        return 0;
    }

    if (!read_at(file, 0, probe->encrypted_prefix, prefix_length)) {
        fclose(file);
        return 0;
    }
    probe->encrypted_prefix_length = prefix_length;

    if (probe->layout == LAYOUT_PARTIAL_10K) {
        uint64_t original_size = probe->file_size - PARTIAL_TRAILER_SIZE;

        if (!read_at(file, original_size - 32ULL, probe->tail_previous, 16)
            || !read_at(file, original_size - 16ULL, probe->tail_last, 16)) {
            fclose(file);
            return 0;
        }
        probe->has_tail = 1;
    } else if (probe->layout == LAYOUT_WHOLE_FILE) {
        if (probe->file_size >= 32ULL) {
            if (!read_at(file, probe->file_size - 32ULL, probe->tail_previous, 16)
                || !read_at(file, probe->file_size - 16ULL, probe->tail_last, 16)) {
                fclose(file);
                return 0;
            }
        } else {
            memset(probe->tail_previous, 0, 16);
            if (!read_at(file, 0, probe->tail_last, 16)) {
                fclose(file);
                return 0;
            }
        }
        probe->has_tail = 1;
    } else if (probe->layout == LAYOUT_R543T_TINY) {
        uint64_t main_size = probe->file_size - 16ULL;

        if (main_size >= 32ULL) {
            if (!read_at(file, main_size - 32ULL, probe->legacy_main_previous, 16)
                || !read_at(file, main_size - 16ULL, probe->legacy_main_last, 16)) {
                fclose(file);
                return 0;
            }
        } else {
            memset(probe->legacy_main_previous, 0, 16);
            if (!read_at(file, 0, probe->legacy_main_last, 16)) {
                fclose(file);
                return 0;
            }
        }

        if (!read_at(file, main_size, probe->legacy_extra_block, 16)) {
            fclose(file);
            return 0;
        }
        probe->has_legacy_tail = 1;
    }

    fclose(file);
    return 1;
}

static int pkcs7_tail_valid(
    const uint8_t previous_ciphertext[16],
    const uint8_t last_ciphertext[16],
    const uint8_t round_keys[240])
{
    uint8_t plaintext[16];
    aes256_decrypt_block(last_ciphertext, plaintext, round_keys);

    for (uint32_t i = 0; i < 16; i++) {
        plaintext[i] ^= previous_ciphertext[i];
    }

    uint8_t padding = plaintext[15];
    if (padding < 1 || padding > 16) {
        return 0;
    }

    for (uint32_t i = 0; i < padding; i++) {
        if (plaintext[15U - i] != padding) {
            return 0;
        }
    }
    return 1;
}

static int decrypts_to_full_padding_block(
    const uint8_t ciphertext[16],
    const uint8_t round_keys[240])
{
    uint8_t plaintext[16];
    aes256_decrypt_block(ciphertext, plaintext, round_keys);

    for (uint32_t i = 0; i < 16; i++) {
        if (plaintext[i] != 0x10) {
            return 0;
        }
    }
    return 1;
}

static int probe_padding_valid(
    const struct probe_info *probe,
    const uint8_t round_keys[240])
{
    if (probe->layout == LAYOUT_PARTIAL_10K) {
        if (!probe->has_tail) {
            return 0;
        }

        uint8_t plaintext[16];
        aes256_decrypt_block(probe->tail_last, plaintext, round_keys);
        for (uint32_t i = 0; i < 16; i++) {
            if ((uint8_t)(plaintext[i] ^ probe->tail_previous[i]) != 0x10) {
                return 0;
            }
        }
        return 1;
    }

    if (probe->layout == LAYOUT_WHOLE_FILE) {
        return probe->has_tail
            && pkcs7_tail_valid(probe->tail_previous, probe->tail_last, round_keys);
    }

    if (probe->layout == LAYOUT_R543T_TINY) {
        return probe->has_legacy_tail
            && pkcs7_tail_valid(
                probe->legacy_main_previous,
                probe->legacy_main_last,
                round_keys)
            && decrypts_to_full_padding_block(
                probe->legacy_extra_block,
                round_keys);
    }

    return 0;
}

static uint32_t decrypt_probe_prefix(
    const struct probe_info *probe,
    const uint8_t round_keys[240],
    uint8_t output[PROBE_PREFIX_BYTES])
{
    uint8_t previous[16] = {0};
    uint8_t block[16];
    uint32_t blocks = probe->encrypted_prefix_length / 16U;

    for (uint32_t b = 0; b < blocks; b++) {
        const uint8_t *ciphertext = probe->encrypted_prefix + 16U * b;
        aes256_decrypt_block(ciphertext, block, round_keys);

        for (uint32_t i = 0; i < 16; i++) {
            output[16U * b + i] = block[i] ^ previous[i];
        }

        memcpy(previous, ciphertext, 16);
    }

    return blocks * 16U;
}

/* ------------------------------------------------------------------------- */
/* Multithreaded brute-force                                                 */
/* ------------------------------------------------------------------------- */

struct search_context {
    struct probe_info probe;
    struct magic_pattern patterns[MAX_MAGIC_PATTERNS];
    uint32_t pattern_count;
    int text_mode;

    uint64_t start;
    uint64_t count;
    uint32_t step;
    uint32_t threads;
    int verify_padding;

    atomic_u32 found;
    uint32_t found_handle;
    atomic_u64 processed;
    atomic_u32 active_threads;
};

struct worker_argument {
    struct search_context *context;
    uint32_t thread_index;
};

static int candidate_matches(
    const struct search_context *context,
    const uint8_t round_keys[240])
{
    uint8_t plaintext[PROBE_PREFIX_BYTES];
    uint32_t length = decrypt_probe_prefix(&context->probe, round_keys, plaintext);

    int header_matches = context->text_mode
        ? looks_like_text(plaintext, length)
        : magic_patterns_match(
            plaintext,
            length,
            context->patterns,
            context->pattern_count);

    if (!header_matches) {
        return 0;
    }

    if (context->verify_padding
        && !probe_padding_valid(&context->probe, round_keys)) {
        return 0;
    }

    return 1;
}

static void worker_run(struct worker_argument *argument)
{
    struct search_context *context = argument->context;
    uint64_t index = argument->thread_index;
    uint64_t local_processed = 0;
    uint8_t key[32];
    uint8_t round_keys[240];

    while (index < context->count && !atomic_load_u32(&context->found)) {
        uint64_t candidate_value =
            context->start + index * (uint64_t)context->step;
        uint32_t handle = (uint32_t)candidate_value;

        derive_file_key(handle, key);
        aes256_expand_key(key, round_keys);

        if (candidate_matches(context, round_keys)) {
            if (atomic_try_set(&context->found)) {
                context->found_handle = handle;
            }
            break;
        }

        index += context->threads;
        local_processed++;

        if (local_processed >= PROGRESS_BATCH) {
            atomic_add_u64(&context->processed, local_processed);
            local_processed = 0;
        }
    }

    if (local_processed) {
        atomic_add_u64(&context->processed, local_processed);
    }
    atomic_dec_u32(&context->active_threads);
}

#ifdef _WIN32
static DWORD WINAPI worker_entry(LPVOID opaque)
{
    worker_run((struct worker_argument *)opaque);
    return 0;
}
#else
static void *worker_entry(void *opaque)
{
    worker_run((struct worker_argument *)opaque);
    return NULL;
}
#endif

static void print_hex(const uint8_t *bytes, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

static int brute_force_handle(
    const char *path,
    const char *suffix,
    const char *extension,
    const struct options *options,
    uint32_t *recovered_handle)
{
    struct search_context context;
    struct worker_argument worker_arguments[MAX_THREADS];
    thread_handle threads[MAX_THREADS];
    const char *type_name = NULL;
    uint32_t thread_count = options->threads;

    memset(&context, 0, sizeof(context));

    if (!prepare_probe(path, suffix, &context.probe)) {
        printf("[!] unsupported ransomware layout: %s\n", path);
        return 0;
    }

    if (options->manual_magic) {
        uint32_t length = 0;
        if (!parse_hex(
                options->manual_magic,
                context.patterns[0].bytes,
                &length)) {
            printf("[!] invalid --magic value\n");
            return 0;
        }

        context.patterns[0].length = length;
        context.patterns[0].offset = options->manual_magic_offset;
        context.patterns[0].label = "manual";
        context.pattern_count = 1;
        type_name = "manual";
    } else {
        const char *type = options->forced_type
            ? options->forced_type
            : extension;

        if (!load_type_patterns(
                type,
                context.patterns,
                &context.pattern_count,
                &context.text_mode,
                &type_name)) {
            printf(
                "[!] no automatic signature for '%s'; use --magic HEX or --type TYPE\n",
                type && *type ? type : "unknown");
            return 0;
        }
    }

    if (context.text_mode && context.probe.encrypted_prefix_length < 32U) {
        printf("[!] text probe is too short for safe automatic matching; use --magic\n");
        return 0;
    }

    if (thread_count == 0) {
        thread_count = 1;
    }
    if (thread_count > MAX_THREADS) {
        thread_count = MAX_THREADS;
    }

    context.start = options->start;
    context.step = options->step;
    context.threads = thread_count;
    context.verify_padding = options->verify_padding;
    context.count =
        (options->end - options->start) / (uint64_t)options->step + 1ULL;
    context.active_threads = thread_count;

    printf(
        "[i] probe=%s size=%" PRIu64 " layout=%s type=%s\n",
        path,
        context.probe.file_size,
        layout_name(context.probe.layout),
        type_name ? type_name : "?");

    if (context.text_mode) {
        printf("[i] matcher=text-prefix\n");
    } else {
        printf("[i] matcher=");
        for (uint32_t i = 0; i < context.pattern_count; i++) {
            if (i) {
                printf(", ");
            }
            printf("%s", context.patterns[i].label);
        }
        printf("\n");
    }

    printf(
        "[i] range=0x%08" PRIx64 "..0x%08" PRIx64
        " step=%u candidates=%" PRIu64 " threads=%u padding_verify=%s\n",
        options->start,
        options->end,
        options->step,
        context.count,
        thread_count,
        context.verify_padding ? "yes" : "no");
    fflush(stdout);

    uint64_t started = monotonic_ms();
    uint64_t last_progress = started;

    for (uint32_t i = 0; i < thread_count; i++) {
        worker_arguments[i].context = &context;
        worker_arguments[i].thread_index = i;

#ifdef _WIN32
        threads[i] = CreateThread(
            NULL,
            0,
            worker_entry,
            &worker_arguments[i],
            0,
            NULL);
        if (!threads[i]) {
            printf("[!] CreateThread failed\n");
            return 0;
        }
#else
        if (pthread_create(
                &threads[i],
                NULL,
                worker_entry,
                &worker_arguments[i]) != 0) {
            printf("[!] pthread_create failed\n");
            return 0;
        }
#endif
    }

    while (atomic_load_u32(&context.active_threads) > 0
        && !atomic_load_u32(&context.found)) {
        uint64_t now = monotonic_ms();
        if (now - last_progress >= 2000ULL) {
            uint64_t processed = atomic_load_u64(&context.processed);
            double elapsed_seconds = (double)(now - started) / 1000.0;
            double rate = elapsed_seconds > 0
                ? (double)processed / elapsed_seconds
                : 0.0;
            double remaining = rate > 0
                ? (double)(context.count - processed) / rate
                : 0.0;

            printf(
                "[i] %.2f%%  %.2f M/s  ETA %.1f s\n",
                100.0 * (double)processed / (double)context.count,
                rate / 1000000.0,
                remaining);
            fflush(stdout);
            last_progress = now;
        }
        sleep_ms(100);
    }

    for (uint32_t i = 0; i < thread_count; i++) {
#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }

    uint64_t elapsed = monotonic_ms() - started;
    uint64_t processed = atomic_load_u64(&context.processed);
    double elapsed_seconds = (double)elapsed / 1000.0;

    printf(
        "[i] processed=%" PRIu64 " elapsed=%.3f s rate=%.2f M/s\n",
        processed,
        elapsed_seconds,
        elapsed_seconds > 0
            ? (double)processed / elapsed_seconds / 1000000.0
            : 0.0);

    if (!atomic_load_u32(&context.found)) {
        printf("[-] no matching handle found\n");
        return 0;
    }

    *recovered_handle = context.found_handle;

    uint8_t key[32];
    uint8_t raw_handle[4];
    derive_file_key(*recovered_handle, key);
    store_u32_le(raw_handle, *recovered_handle);

    printf("[+] handle=0x%08x raw_le=", *recovered_handle);
    print_hex(raw_handle, 4);
    printf("\n[+] derived_aes256_key=");
    print_hex(key, 32);
    printf("\n");
    fflush(stdout);

    return 1;
}

/* ------------------------------------------------------------------------- */
/* File decryption                                                           */
/* ------------------------------------------------------------------------- */

static int decrypt_partial_chunk(
    FILE *input,
    uint64_t offset,
    FILE *output,
    const uint8_t round_keys[240])
{
    uint8_t *ciphertext = (uint8_t *)malloc(PARTIAL_CIPHER_CHUNK);
    if (!ciphertext) {
        return 0;
    }

    if (!read_at(input, offset, ciphertext, PARTIAL_CIPHER_CHUNK)) {
        free(ciphertext);
        return 0;
    }

    uint8_t previous[16] = {0};
    uint8_t plaintext[16];
    uint32_t block_count = PARTIAL_CIPHER_CHUNK / AES_BLOCK_SIZE;

    for (uint32_t block = 0; block < block_count; block++) {
        const uint8_t *current = ciphertext + block * 16U;
        aes256_decrypt_block(current, plaintext, round_keys);

        for (uint32_t i = 0; i < 16; i++) {
            plaintext[i] ^= previous[i];
        }
        memcpy(previous, current, 16);

        if (block + 1 == block_count) {
            for (uint32_t i = 0; i < 16; i++) {
                if (plaintext[i] != 0x10) {
                    free(ciphertext);
                    return 0;
                }
            }
        } else if (fwrite(plaintext, 1, 16, output) != 16) {
            free(ciphertext);
            return 0;
        }
    }

    free(ciphertext);
    return 1;
}

static int copy_range(
    FILE *input,
    uint64_t offset,
    uint64_t length,
    FILE *output)
{
    uint8_t *buffer = (uint8_t *)malloc(64U * 1024U);
    if (!buffer) {
        return 0;
    }

    if (!seek_file(input, offset)) {
        free(buffer);
        return 0;
    }

    while (length > 0) {
        size_t chunk = length > 64U * 1024U
            ? 64U * 1024U
            : (size_t)length;

        if (fread(buffer, 1, chunk, input) != chunk
            || fwrite(buffer, 1, chunk, output) != chunk) {
            free(buffer);
            return 0;
        }
        length -= chunk;
    }

    free(buffer);
    return 1;
}

static int decrypt_partial_file(
    FILE *input,
    FILE *output,
    uint64_t encrypted_size,
    const uint8_t round_keys[240])
{
    uint64_t original_size = encrypted_size - PARTIAL_TRAILER_SIZE;
    if (original_size < 20032ULL) {
        return 0;
    }

    uint8_t saved_bytes[32];
    if (!read_at(input, original_size, saved_bytes, sizeof(saved_bytes))) {
        return 0;
    }

    if (!decrypt_partial_chunk(input, 0, output, round_keys)) {
        return 0;
    }

    if (fwrite(saved_bytes, 1, 16, output) != 16) {
        return 0;
    }

    uint64_t middle_length = original_size - 2ULL * PARTIAL_CIPHER_CHUNK;
    if (!copy_range(input, PARTIAL_CIPHER_CHUNK, middle_length, output)) {
        return 0;
    }

    if (!decrypt_partial_chunk(
            input,
            original_size - PARTIAL_CIPHER_CHUNK,
            output,
            round_keys)) {
        return 0;
    }

    return fwrite(saved_bytes + 16, 1, 16, output) == 16;
}

static int decrypt_whole_file_length(
    FILE *input,
    FILE *output,
    uint64_t ciphertext_length,
    const uint8_t round_keys[240])
{
    if (ciphertext_length < 16ULL || ciphertext_length % 16ULL != 0) {
        return 0;
    }

    if (!seek_file(input, 0)) {
        return 0;
    }

    uint64_t block_count = ciphertext_length / 16ULL;
    uint8_t previous[16] = {0};
    uint8_t ciphertext[16];
    uint8_t plaintext[16];

    for (uint64_t block = 0; block < block_count; block++) {
        if (fread(ciphertext, 1, 16, input) != 16) {
            return 0;
        }

        aes256_decrypt_block(ciphertext, plaintext, round_keys);
        for (uint32_t i = 0; i < 16; i++) {
            plaintext[i] ^= previous[i];
        }
        memcpy(previous, ciphertext, 16);

        if (block + 1 < block_count) {
            if (fwrite(plaintext, 1, 16, output) != 16) {
                return 0;
            }
        } else {
            uint8_t padding = plaintext[15];
            if (padding < 1 || padding > 16) {
                return 0;
            }
            for (uint32_t i = 0; i < padding; i++) {
                if (plaintext[15U - i] != padding) {
                    return 0;
                }
            }

            size_t final_length = 16U - padding;
            if (final_length > 0
                && fwrite(plaintext, 1, final_length, output) != final_length) {
                return 0;
            }
        }
    }

    return 1;
}

static int decrypt_r543t_tiny_file(
    FILE *input,
    FILE *output,
    uint64_t encrypted_size,
    const uint8_t round_keys[240])
{
    if (encrypted_size < 32ULL) {
        return 0;
    }

    uint64_t main_ciphertext_size = encrypted_size - 16ULL;
    if (main_ciphertext_size < 16ULL || main_ciphertext_size % 16ULL != 0) {
        return 0;
    }

    uint8_t extra_ciphertext[16];
    uint8_t extra_plaintext[16];

    if (!read_at(input, main_ciphertext_size, extra_ciphertext, 16)) {
        return 0;
    }

    aes256_decrypt_block(extra_ciphertext, extra_plaintext, round_keys);
    for (uint32_t i = 0; i < 16; i++) {
        if (extra_plaintext[i] != 0x10) {
            return 0;
        }
    }

    return decrypt_whole_file_length(
        input,
        output,
        main_ciphertext_size,
        round_keys);
}

static int create_directory_one(const char *path)
{
#ifdef _WIN32
    if (CreateDirectoryA(path, NULL)) {
        return 1;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(path, 0755) == 0 || errno == EEXIST;
#endif
}

static int ensure_directory(const char *path)
{
    char buffer[PATH_BUFFER_SIZE];
    size_t length = strlen(path);

    if (length >= sizeof(buffer)) {
        return 0;
    }

    copy_string(buffer, sizeof(buffer), path);

    for (size_t i = 1; i < length; i++) {
        if (buffer[i] == '/' || buffer[i] == '\\') {
            char saved = buffer[i];
            buffer[i] = '\0';

            /* Do not try to create "C:" on Windows. */
            if (!(i == 2 && buffer[1] == ':') && buffer[0] != '\0') {
                create_directory_one(buffer);
            }

            buffer[i] = saved;
        }
    }

    return create_directory_one(buffer);
}

static int ensure_parent_directory(const char *path)
{
    char buffer[PATH_BUFFER_SIZE];
    size_t length = strlen(path);
    size_t last_separator = 0;

    if (length >= sizeof(buffer)) {
        return 0;
    }

    for (size_t i = 0; i < length; i++) {
        if (path[i] == '/' || path[i] == '\\') {
            last_separator = i;
        }
    }

    if (last_separator == 0) {
        return 1;
    }

    memcpy(buffer, path, last_separator);
    buffer[last_separator] = '\0';
    return ensure_directory(buffer);
}

static int recover_file(
    const char *source,
    const char *destination,
    const char *suffix,
    uint32_t handle,
    int force,
    int dry_run)
{
    FILE *input = fopen(source, "rb");
    if (!input) {
        return 0;
    }

    uint64_t size;
    if (!file_size(input, &size)) {
        fclose(input);
        return 0;
    }

    enum layout_kind layout = detect_layout(suffix, size);
    if (layout == LAYOUT_UNKNOWN) {
        fclose(input);
        return 0;
    }

    uint8_t key[32];
    uint8_t round_keys[240];
    derive_file_key(handle, key);
    aes256_expand_key(key, round_keys);

    struct probe_info probe;
    if (!prepare_probe(source, suffix, &probe)
        || !probe_padding_valid(&probe, round_keys)) {
        fclose(input);
        return 0;
    }

    if (dry_run) {
        fclose(input);
        return 1;
    }

    if (!force) {
        FILE *existing = fopen(destination, "rb");
        if (existing) {
            fclose(existing);
            fclose(input);
            return 0;
        }
    }

    if (!ensure_parent_directory(destination)) {
        fclose(input);
        return 0;
    }

    FILE *output = fopen(destination, "wb");
    if (!output) {
        fclose(input);
        return 0;
    }

    int success = 0;
    if (layout == LAYOUT_PARTIAL_10K) {
        success = decrypt_partial_file(input, output, size, round_keys);
    } else if (layout == LAYOUT_WHOLE_FILE) {
        success = decrypt_whole_file_length(input, output, size, round_keys);
    } else if (layout == LAYOUT_R543T_TINY) {
        success = decrypt_r543t_tiny_file(input, output, size, round_keys);
    }

    fclose(output);
    fclose(input);

    if (!success) {
        remove(destination);
    }
    return success;
}

/* ------------------------------------------------------------------------- */
/* Directory scanning and automatic recovery                                 */
/* ------------------------------------------------------------------------- */

static int vector_push(
    struct file_vector *vector,
    const char *full_path,
    const char *relative_path,
    uint64_t size,
    const char *suffix)
{
    if (vector->count == vector->capacity) {
        size_t new_capacity = vector->capacity ? vector->capacity * 2U : 64U;
        struct file_entry *new_items = (struct file_entry *)realloc(
            vector->items,
            new_capacity * sizeof(*new_items));
        if (!new_items) {
            return 0;
        }
        vector->items = new_items;
        vector->capacity = new_capacity;
    }

    struct file_entry *entry = &vector->items[vector->count++];
    memset(entry, 0, sizeof(*entry));

    entry->full_path = duplicate_string(full_path);
    entry->relative_path = duplicate_string(relative_path);
    entry->size = size;
    copy_string(entry->ransomware_suffix, sizeof(entry->ransomware_suffix), suffix);
    original_extension(full_path, suffix, entry->original_extension);

    return entry->full_path != NULL && entry->relative_path != NULL;
}

static void vector_free(struct file_vector *vector)
{
    for (size_t i = 0; i < vector->count; i++) {
        free(vector->items[i].full_path);
        free(vector->items[i].relative_path);
    }
    free(vector->items);
    memset(vector, 0, sizeof(*vector));
}

static int scan_tree_recursive(
    const char *root,
    const char *relative_directory,
    struct file_vector *files)
{
    char directory[PATH_BUFFER_SIZE];
    char child_relative[PATH_BUFFER_SIZE];
    char full_path[PATH_BUFFER_SIZE];

    if (relative_directory && *relative_directory) {
        if (!join_path(
                directory,
                sizeof(directory),
                root,
                relative_directory)) {
            return 0;
        }
    } else {
        copy_string(directory, sizeof(directory), root);
    }

#ifdef _WIN32
    char pattern[PATH_BUFFER_SIZE];
    if (!join_path(pattern, sizeof(pattern), directory, "*")) {
        return 0;
    }

    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(pattern, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        const char *name = find_data.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if (relative_directory && *relative_directory) {
            if (!join_path(
                    child_relative,
                    sizeof(child_relative),
                    relative_directory,
                    name)) {
                continue;
            }
        } else {
            copy_string(child_relative, sizeof(child_relative), name);
        }

        if (!join_path(full_path, sizeof(full_path), root, child_relative)) {
            continue;
        }

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_tree_recursive(root, child_relative, files);
            continue;
        }

        const char *suffix = ransomware_suffix(name);
        if (!suffix) {
            continue;
        }

        uint64_t size = ((uint64_t)find_data.nFileSizeHigh << 32)
            | find_data.nFileSizeLow;

        if (!vector_push(files, full_path, child_relative, size, suffix)) {
            FindClose(find_handle);
            return 0;
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
#else
    DIR *dir = opendir(directory);
    if (!dir) {
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if (relative_directory && *relative_directory) {
            if (!join_path(
                    child_relative,
                    sizeof(child_relative),
                    relative_directory,
                    name)) {
                continue;
            }
        } else {
            copy_string(child_relative, sizeof(child_relative), name);
        }

        if (!join_path(full_path, sizeof(full_path), root, child_relative)) {
            continue;
        }

        struct stat stat_buffer;
        if (stat(full_path, &stat_buffer) != 0) {
            continue;
        }

        if (S_ISDIR(stat_buffer.st_mode)) {
            scan_tree_recursive(root, child_relative, files);
            continue;
        }
        if (!S_ISREG(stat_buffer.st_mode)) {
            continue;
        }

        const char *suffix = ransomware_suffix(name);
        if (!suffix) {
            continue;
        }

        if (!vector_push(
                files,
                full_path,
                child_relative,
                (uint64_t)stat_buffer.st_size,
                suffix)) {
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
#endif

    return 1;
}

static int output_path_for_entry(
    char *destination,
    size_t capacity,
    const char *output_root,
    const struct file_entry *entry)
{
    char relative[PATH_BUFFER_SIZE];
    size_t path_length = strlen(entry->relative_path);
    size_t suffix_length = strlen(entry->ransomware_suffix);

    if (path_length <= suffix_length
        || path_length - suffix_length >= sizeof(relative)) {
        return 0;
    }

    size_t clean_length = path_length - suffix_length;
    memcpy(relative, entry->relative_path, clean_length);
    relative[clean_length] = '\0';

    return join_path(destination, capacity, output_root, relative);
}

static int copy_file_raw(
    const char *source,
    const char *destination,
    int force,
    int dry_run)
{
    if (dry_run) {
        return 1;
    }

    if (!force) {
        FILE *existing = fopen(destination, "rb");
        if (existing) {
            fclose(existing);
            return 0;
        }
    }

    if (!ensure_parent_directory(destination)) {
        return 0;
    }

    FILE *input = fopen(source, "rb");
    if (!input) {
        return 0;
    }

    FILE *output = fopen(destination, "wb");
    if (!output) {
        fclose(input);
        return 0;
    }

    uint8_t *buffer = (uint8_t *)malloc(64U * 1024U);
    if (!buffer) {
        fclose(output);
        fclose(input);
        return 0;
    }

    int success = 1;
    for (;;) {
        size_t read_length = fread(buffer, 1, 64U * 1024U, input);
        if (read_length > 0
            && fwrite(buffer, 1, read_length, output) != read_length) {
            success = 0;
            break;
        }
        if (read_length < 64U * 1024U) {
            break;
        }
    }

    free(buffer);
    fclose(output);
    fclose(input);

    if (!success) {
        remove(destination);
    }
    return success;
}

static int plaintext_matches_expected_type(
    const char *path,
    const char *extension)
{
    struct magic_pattern patterns[MAX_MAGIC_PATTERNS];
    uint32_t count = 0;
    int text_mode = 0;
    const char *type_name = NULL;

    if (!load_type_patterns(
            extension,
            patterns,
            &count,
            &text_mode,
            &type_name)) {
        return 0;
    }

    FILE *file = fopen(path, "rb");
    if (!file) {
        return 0;
    }

    uint8_t prefix[PROBE_PREFIX_BYTES];
    size_t length = fread(prefix, 1, sizeof(prefix), file);
    fclose(file);

    if (text_mode) {
        return looks_like_text(prefix, (uint32_t)length);
    }
    return magic_patterns_match(prefix, (uint32_t)length, patterns, count);
}

static int handle_is_known(
    const uint32_t *handles,
    uint32_t handle_count,
    uint32_t handle)
{
    for (uint32_t i = 0; i < handle_count; i++) {
        if (handles[i] == handle) {
            return 1;
        }
    }
    return 0;
}

static int handle_valid_for_file(
    const struct file_entry *entry,
    uint32_t handle,
    int trust_key)
{
    struct probe_info probe;
    if (!prepare_probe(
            entry->full_path,
            entry->ransomware_suffix,
            &probe)) {
        return 0;
    }

    uint8_t key[32];
    uint8_t round_keys[240];
    derive_file_key(handle, key);
    aes256_expand_key(key, round_keys);

    if (!probe_padding_valid(&probe, round_keys)) {
        return 0;
    }

    /*
     * For whole-file ciphertext, padding alone is a weaker oracle. Unless the
     * caller explicitly trusts the supplied/discovered key, also validate the
     * recovered prefix against the original file extension.
     */
    if (probe.layout == LAYOUT_WHOLE_FILE && !trust_key) {
        struct magic_pattern patterns[MAX_MAGIC_PATTERNS];
        uint32_t pattern_count = 0;
        int text_mode = 0;
        const char *type_name = NULL;

        if (!load_type_patterns(
                entry->original_extension,
                patterns,
                &pattern_count,
                &text_mode,
                &type_name)) {
            return 0;
        }

        uint8_t plaintext[PROBE_PREFIX_BYTES];
        uint32_t length = decrypt_probe_prefix(&probe, round_keys, plaintext);

        if (text_mode) {
            if (!looks_like_text(plaintext, length)) {
                return 0;
            }
        } else if (!magic_patterns_match(
                plaintext,
                length,
                patterns,
                pattern_count)) {
            return 0;
        }
    }

    return 1;
}

static int probe_score(const struct file_entry *entry)
{
    struct magic_pattern patterns[MAX_MAGIC_PATTERNS];
    uint32_t count = 0;
    int text_mode = 0;
    const char *type_name = NULL;

    if (detect_layout(entry->ransomware_suffix, entry->size) == LAYOUT_UNKNOWN) {
        return -1;
    }

    if (!load_type_patterns(
            entry->original_extension,
            patterns,
            &count,
            &text_mode,
            &type_name)) {
        return -1;
    }

    int score = text_mode ? 10 : 40;
    if (detect_layout(entry->ransomware_suffix, entry->size)
        == LAYOUT_PARTIAL_10K) {
        score += 20;
    }

    if (!text_mode) {
        uint32_t longest = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (patterns[i].length > longest) {
                longest = patterns[i].length;
            }
        }
        score += (int)longest;
    }

    return score;
}

static int read_sslog_handles(
    const char *path,
    uint32_t handles[MAX_RECOVERY_KEYS],
    uint32_t *handle_count)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        return 0;
    }

    uint8_t bytes[4];
    while (*handle_count < MAX_RECOVERY_KEYS
        && fread(bytes, 1, 4, file) == 4) {
        uint32_t handle = load_u32_le(bytes);
        if (!handle_is_known(handles, *handle_count, handle)) {
            handles[(*handle_count)++] = handle;
        }
    }

    fclose(file);
    return 1;
}

static int auto_recover(
    const char *input_root,
    const char *output_root,
    const struct options *options,
    const char *sslog,
    int have_initial_handle,
    uint32_t initial_handle)
{
    struct file_vector files = {0};
    uint32_t handles[MAX_RECOVERY_KEYS];
    uint32_t handle_count = 0;
    uint32_t recovered_count = 0;
    uint32_t passthrough_count = 0;
    uint32_t unresolved_count = 0;
    char output_path[PATH_BUFFER_SIZE];
    char report_path[PATH_BUFFER_SIZE] = {0};

    if (!scan_tree_recursive(input_root, "", &files)) {
        printf("[!] cannot scan directory: %s\n", input_root);
        vector_free(&files);
        return 1;
    }

    printf("[i] found %" PRIu64 " ransomware-suffixed file(s)\n", (uint64_t)files.count);
    if (files.count == 0) {
        vector_free(&files);
        return 0;
    }

    if (!options->dry_run && !ensure_directory(output_root)) {
        printf("[!] cannot create output directory: %s\n", output_root);
        vector_free(&files);
        return 1;
    }

    if (have_initial_handle) {
        handles[handle_count++] = initial_handle;
    }

    if (sslog
        && !read_sslog_handles(sslog, handles, &handle_count)) {
        printf("[!] cannot read sslog: %s\n", sslog);
        vector_free(&files);
        return 1;
    }

    if (handle_count) {
        printf("[i] loaded %u candidate handle(s)\n", handle_count);
    }

    /* First handle files that only received the ransomware extension. */
    for (size_t i = 0; i < files.count; i++) {
        struct file_entry *entry = &files.items[i];

        if (!plaintext_matches_expected_type(
                entry->full_path,
                entry->original_extension)) {
            continue;
        }

        if (!output_path_for_entry(
                output_path,
                sizeof(output_path),
                output_root,
                entry)) {
            continue;
        }

        if (copy_file_raw(
                entry->full_path,
                output_path,
                options->force,
                options->dry_run)) {
            entry->resolved = 1;
            entry->plaintext_renamed = 1;
            copy_string(entry->status, sizeof(entry->status), "plaintext-renamed");
            passthrough_count++;
            printf("[+] plaintext passthrough: %s\n", entry->relative_path);
        }
    }

    for (;;) {
        int made_progress = 0;

        /* Apply every already known handle to unresolved files. */
        for (size_t i = 0; i < files.count; i++) {
            struct file_entry *entry = &files.items[i];
            if (entry->resolved) {
                continue;
            }

            for (uint32_t k = 0; k < handle_count; k++) {
                if (!handle_valid_for_file(
                        entry,
                        handles[k],
                        options->trust_key)) {
                    continue;
                }

                if (!output_path_for_entry(
                        output_path,
                        sizeof(output_path),
                        output_root,
                        entry)) {
                    break;
                }

                if (recover_file(
                        entry->full_path,
                        output_path,
                        entry->ransomware_suffix,
                        handles[k],
                        options->force,
                        options->dry_run)) {
                    entry->resolved = 1;
                    entry->handle = handles[k];
                    copy_string(entry->status, sizeof(entry->status), "recovered");
                    recovered_count++;
                    made_progress = 1;

                    printf(
                        "[+] recovered: %s -> %s [0x%08x]\n",
                        entry->relative_path,
                        output_path,
                        handles[k]);
                }
                break;
            }
        }

        if (made_progress) {
            continue;
        }

        /* Pick the best unresolved file as the next brute-force oracle. */
        int best_index = -1;
        int best_score = -1;

        for (size_t i = 0; i < files.count; i++) {
            struct file_entry *entry = &files.items[i];
            if (entry->resolved || entry->tried_as_probe) {
                continue;
            }

            int score = probe_score(entry);
            if (score > best_score) {
                best_score = score;
                best_index = (int)i;
            }
        }

        if (best_index < 0) {
            break;
        }

        if (handle_count > 0 && !options->multi_key) {
            break;
        }

        struct file_entry *probe_entry = &files.items[best_index];
        probe_entry->tried_as_probe = 1;

        printf(
            "[i] discovering key from %s (%s)\n",
            probe_entry->relative_path,
            probe_entry->original_extension);

        struct options probe_options = *options;
        probe_options.manual_magic = NULL;
        probe_options.forced_type = NULL;

        uint32_t recovered_handle;
        if (!brute_force_handle(
                probe_entry->full_path,
                probe_entry->ransomware_suffix,
                probe_entry->original_extension,
                &probe_options,
                &recovered_handle)) {
            printf(
                "[-] unable to recover a handle from %s\n",
                probe_entry->relative_path);
            continue;
        }

        if (!handle_is_known(handles, handle_count, recovered_handle)) {
            if (handle_count >= MAX_RECOVERY_KEYS) {
                printf("[!] maximum number of recovery keys reached\n");
                break;
            }
            handles[handle_count++] = recovered_handle;
            printf(
                "[+] discovered key #%u: handle=0x%08x\n",
                handle_count,
                recovered_handle);
        } else {
            printf("[i] probe rediscovered an existing handle\n");
        }
    }

    FILE *report = NULL;
    if (!options->dry_run
        && join_path(
            report_path,
            sizeof(report_path),
            output_root,
            "_r543t_recovery_report.tsv")) {
        report = fopen(report_path, "wb");
        if (report) {
            fputs("source\tstatus\thandle\toutput\n", report);
        }
    }

    for (size_t i = 0; i < files.count; i++) {
        struct file_entry *entry = &files.items[i];

        if (!entry->resolved) {
            unresolved_count++;
            copy_string(entry->status, sizeof(entry->status), "unresolved");
            printf(
                "[-] unresolved: %s (layout=%s ext=%s)\n",
                entry->relative_path,
                layout_name(detect_layout(entry->ransomware_suffix, entry->size)),
                entry->original_extension);
        }

        if (report) {
            output_path_for_entry(
                output_path,
                sizeof(output_path),
                output_root,
                entry);

            fprintf(report, "%s\t%s\t", entry->relative_path, entry->status);
            if (entry->handle) {
                fprintf(report, "0x%08x", entry->handle);
            }
            fprintf(report, "\t%s\n", entry->resolved ? output_path : "");
        }
    }

    if (report) {
        fclose(report);
    }

    printf(
        "[i] complete: recovered=%u plaintext_renamed=%u unresolved=%u keys=%u\n",
        recovered_count,
        passthrough_count,
        unresolved_count,
        handle_count);

    if (report_path[0] != '\0' && !options->dry_run) {
        printf("[i] report=%s\n", report_path);
    }

    vector_free(&files);
    return unresolved_count ? 2 : 0;
}

/* ------------------------------------------------------------------------- */
/* CLI                                                                       */
/* ------------------------------------------------------------------------- */

static int self_test(void)
{
    static const uint32_t test_handle = 0x01234568U;
    static const uint8_t expected_derived_key[32] = {
        0x03, 0xfa, 0xe7, 0xf0, 0x05, 0x1b, 0x03, 0x3e,
        0x6c, 0x71, 0x2e, 0x1e, 0x47, 0xce, 0x7e, 0x24,
        0xe6, 0x9f, 0x61, 0x8d, 0x68, 0x33, 0x03, 0x74,
        0x2f, 0xd0, 0x80, 0xaf, 0x6f, 0xca, 0x1a, 0x3c
    };

    static const uint8_t aes_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const uint8_t aes_ciphertext[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    static const uint8_t aes_plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    uint8_t derived_key[32];
    derive_file_key(test_handle, derived_key);
    if (memcmp(derived_key, expected_derived_key, sizeof(derived_key)) != 0) {
        printf("[-] self-test failed: CryptoAPI-compatible KDF mismatch\n");
        return 0;
    }

    uint8_t round_keys[240];
    uint8_t decrypted_block[16];
    aes256_expand_key(aes_key, round_keys);
    aes256_decrypt_block(aes_ciphertext, decrypted_block, round_keys);
    if (memcmp(decrypted_block, aes_plaintext, sizeof(decrypted_block)) != 0) {
        printf("[-] self-test failed: AES-256 block decryption mismatch\n");
        return 0;
    }

    printf("[+] self-test OK: KDF and AES-256 implementation validated\n");
    return 1;
}

static void list_types(void)
{
    printf(
        "Automatic types:\n"
        "  JPEG PNG PDF GIF BMP ZIP/DOCX/XLSX/PPTX/JAR/APK OLE DOC/XLS/PPT\n"
        "  PE EXE/DLL/SYS 7Z RAR GZIP BZIP2 SQLite ELF LNK EVTX VHDX QCOW2\n"
        "  TIFF MP4/MOV PCAP PCAPNG and common text/config/log formats.\n");
}

static void usage(const char *program)
{
    printf(
        "r543t / ok75 standalone recovery tool\n\n"
        "Single file:\n"
        "  %s FILE [--magic HEX | --type TYPE] [--output FILE] [options]\n\n"
        "Automatic directory recovery:\n"
        "  %s --auto DIR --output-dir DIR [--multi-key] [options]\n\n"
        "Key sources:\n"
        "  --handle INT          use a known 32-bit HCRYPTKEY\n"
        "  --sslog FILE          read raw little-endian handles from sslog.txt\n\n"
        "Brute-force matching:\n"
        "  --magic HEX           manually specify known plaintext bytes\n"
        "  --magic-offset N      offset of manual magic (default 0)\n"
        "  --type TYPE           force a built-in matcher, e.g. jpg/png/pdf/exe\n"
        "  --threads N           worker threads (default: logical CPU count)\n"
        "  --start INT           first handle candidate (default 0)\n"
        "  --end INT             last handle candidate (default 0xffffffff)\n"
        "  --step N              handle stride (default 4)\n"
        "  --header-only         skip ransomware padding/layout verification\n\n"
        "Recovery behaviour:\n"
        "  --output FILE         single-file output; in --auto mode accepted as\n"
        "                        an alias for --output-dir\n"
        "  --output-dir DIR      output tree for --auto\n"
        "  --multi-key           discover additional handles for unresolved files\n"
        "  --single-key          stop after the first discovered handle\n"
        "  --trust-key           allow unknown whole-file types using padding only\n"
        "  --force               overwrite existing outputs\n"
        "  --dry-run             discover/validate without writing files\n"
        "  --list-types          show built-in type matchers\n"
        "  --self-test           validate the built-in KDF and AES implementation\n\n"
        "Examples:\n"
        "  %s photo.jpg.ok75 --output photo.jpg\n"
        "  %s blob.ok75 --magic 89504E470D0A1A0A --output recovered.png\n"
        "  %s --auto C:\\encrypted --output-dir C:\\recovered --multi-key\n",
        program,
        program,
        program,
        program,
        program);
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);

    if (!text[0] || !end || *end != '\0') {
        return 0;
    }

    *value = (uint64_t)parsed;
    return 1;
}

static int program_main(int argc, char **argv)
{
    struct options options;
    memset(&options, 0, sizeof(options));

    options.threads = logical_cpu_count();
    options.step = 4;
    options.start = 0;
    options.end = 0xffffffffULL;
    options.verify_padding = 1;

    const char *input = NULL;
    const char *output = NULL;
    const char *auto_directory = NULL;
    const char *output_directory = NULL;
    const char *sslog = NULL;

    uint32_t known_handle = 0;
    int have_known_handle = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        const char *argument = argv[i];

        if (strcmp(argument, "--auto") == 0 && i + 1 < argc) {
            auto_directory = argv[++i];
        } else if (strcmp(argument, "--output-dir") == 0 && i + 1 < argc) {
            output_directory = argv[++i];
        } else if (strcmp(argument, "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argument, "--magic") == 0 && i + 1 < argc) {
            options.manual_magic = argv[++i];
        } else if (strcmp(argument, "--magic-offset") == 0 && i + 1 < argc) {
            options.manual_magic_offset = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argument, "--type") == 0 && i + 1 < argc) {
            options.forced_type = argv[++i];
        } else if (strcmp(argument, "--threads") == 0 && i + 1 < argc) {
            options.threads = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argument, "--start") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &options.start)) {
                printf("[!] invalid --start value\n");
                return 1;
            }
        } else if (strcmp(argument, "--end") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &options.end)) {
                printf("[!] invalid --end value\n");
                return 1;
            }
        } else if (strcmp(argument, "--step") == 0 && i + 1 < argc) {
            options.step = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argument, "--handle") == 0 && i + 1 < argc) {
            uint64_t parsed;
            if (!parse_u64(argv[++i], &parsed) || parsed > 0xffffffffULL) {
                printf("[!] --handle must be a 32-bit value\n");
                return 1;
            }
            known_handle = (uint32_t)parsed;
            have_known_handle = 1;
        } else if (strcmp(argument, "--sslog") == 0 && i + 1 < argc) {
            sslog = argv[++i];
        } else if (strcmp(argument, "--header-only") == 0) {
            options.verify_padding = 0;
        } else if (strcmp(argument, "--force") == 0) {
            options.force = 1;
        } else if (strcmp(argument, "--multi-key") == 0) {
            options.multi_key = 1;
        } else if (strcmp(argument, "--single-key") == 0) {
            options.multi_key = 0;
        } else if (strcmp(argument, "--trust-key") == 0) {
            options.trust_key = 1;
        } else if (strcmp(argument, "--dry-run") == 0) {
            options.dry_run = 1;
        } else if (strcmp(argument, "--list-types") == 0) {
            list_types();
            return 0;
        } else if (strcmp(argument, "--self-test") == 0) {
            return self_test() ? 0 : 4;
        } else if (argument[0] == '-') {
            printf("[!] unknown or incomplete option: %s\n", argument);
            usage(argv[0]);
            return 1;
        } else if (!input) {
            input = argument;
        } else {
            printf("[!] unexpected argument: %s\n", argument);
            return 1;
        }
    }

    if (options.threads == 0) {
        options.threads = 1;
    }
    if (options.threads > MAX_THREADS) {
        options.threads = MAX_THREADS;
    }
    if (options.step == 0
        || options.start > options.end
        || options.end > 0xffffffffULL) {
        printf("[!] invalid search range or step\n");
        return 1;
    }

    if (auto_directory) {
        /* Be forgiving: --output is accepted as an alias in auto mode. */
        if (!output_directory) {
            output_directory = output;
        }
        if (!output_directory) {
            printf("[!] --auto requires --output-dir DIR (or --output DIR)\n");
            return 1;
        }

        return auto_recover(
            auto_directory,
            output_directory,
            &options,
            sslog,
            have_known_handle,
            known_handle);
    }

    if (!input) {
        usage(argv[0]);
        return 1;
    }

    const char *suffix = ransomware_suffix(input);
    if (!suffix) {
        printf("[!] input must end in .ok75, .r543t or .ok45\n");
        return 1;
    }

    char extension[32];
    original_extension(input, suffix, extension);

    if (have_known_handle) {
        if (!output) {
            struct file_entry entry;
            memset(&entry, 0, sizeof(entry));
            entry.full_path = (char *)input;
            copy_string(
                entry.ransomware_suffix,
                sizeof(entry.ransomware_suffix),
                suffix);
            copy_string(
                entry.original_extension,
                sizeof(entry.original_extension),
                extension);

            if (handle_valid_for_file(&entry, known_handle, options.trust_key)) {
                printf("[+] handle validates: 0x%08x\n", known_handle);
                return 0;
            }

            printf("[-] handle does not validate\n");
            return 2;
        }

        if (recover_file(
                input,
                output,
                suffix,
                known_handle,
                options.force,
                options.dry_run)) {
            printf("[+] recovered=%s handle=0x%08x\n", output, known_handle);
            return 0;
        }

        printf("[-] handle does not validate or recovery failed\n");
        return 3;
    }

    if (sslog) {
        uint32_t handles[MAX_RECOVERY_KEYS];
        uint32_t handle_count = 0;

        if (!read_sslog_handles(sslog, handles, &handle_count) || handle_count == 0) {
            printf("[!] no handles found in sslog\n");
            return 1;
        }

        struct file_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.full_path = (char *)input;
        copy_string(
            entry.ransomware_suffix,
            sizeof(entry.ransomware_suffix),
            suffix);
        copy_string(
            entry.original_extension,
            sizeof(entry.original_extension),
            extension);

        for (uint32_t i = 0; i < handle_count; i++) {
            if (handle_valid_for_file(&entry, handles[i], options.trust_key)) {
                known_handle = handles[i];
                have_known_handle = 1;
                break;
            }
        }

        if (!have_known_handle) {
            printf("[-] no sslog handle validated\n");
            return 2;
        }

        if (!output) {
            printf("[+] sslog handle validates: 0x%08x\n", known_handle);
            return 0;
        }

        if (recover_file(
                input,
                output,
                suffix,
                known_handle,
                options.force,
                options.dry_run)) {
            printf("[+] recovered=%s handle=0x%08x\n", output, known_handle);
            return 0;
        }

        printf("[!] sslog key validated but recovery failed\n");
        return 3;
    }

    if (!brute_force_handle(
            input,
            suffix,
            extension,
            &options,
            &known_handle)) {
        return 2;
    }

    if (output) {
        if (!recover_file(
                input,
                output,
                suffix,
                known_handle,
                options.force,
                options.dry_run)) {
            printf("[!] key found but recovery failed\n");
            return 3;
        }
        printf("[+] recovered=%s\n", output);
    }

    return 0;
}

int main(int argc, char **argv)
{
    return program_main(argc, argv);
}
