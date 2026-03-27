/*
 * iLLPrimer.c — Encode arbitrary data as a prime number (Carmody method).
 * Clean bordered UI with proper alignment and prime display.
 * gcc -O2 -o iLLPrime iLLPrime.c -lz -lssl -lcrypto -lpthread -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <zlib.h>
#include <getopt.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>

/* ── tunables ────────────────────────────────────────────────────────────── */
#define MAX_SUFFIX_BYTES   8
#define MAX_THREADS       64
#define MR_ROUNDS         25
#define SIEVE_PRIMES    2000
#define PROGRESS_INTERVAL 1ULL

/* ── sieve of small primes ───────────────────────────────────────────────── */

static uint32_t small_primes[SIEVE_PRIMES];
static int      n_small = 0;

static void build_sieve(void) {
    const int LIM = 25000;
    char *s = calloc(LIM, 1);
    s[0] = s[1] = 1;
    for (int i = 2; i < LIM && n_small < SIEVE_PRIMES; i++) {
        if (!s[i]) {
            small_primes[n_small++] = i;
            for (int j = i*2; j < LIM; j += i) s[j] = 1;
        }
    }
    free(s);
}

static uint32_t *build_residues(const BIGNUM *shifted) {
    uint32_t *res = malloc(n_small * sizeof(uint32_t));
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp = BN_new(), *p = BN_new();
    for (int i = 0; i < n_small; i++) {
        BN_set_word(p, small_primes[i]);
        BN_mod(tmp, shifted, p, ctx);
        uint32_t r = (uint32_t)BN_get_word(tmp);
        res[i] = (r == 0) ? 0 : (small_primes[i] - r);
    }
    BN_free(tmp); BN_free(p); BN_CTX_free(ctx);
    return res;
}

/* ── thread ──────────────────────────────────────────────────────────────── */

typedef struct {
    const BIGNUM         *shifted;
    const uint32_t       *sieve_res;
    uint64_t              start;
    uint64_t              stride;
    uint64_t              window;
    BIGNUM               *result;
    int                   found;
    atomic_int           *global_found;
    atomic_int           *threads_done;
    atomic_uint_fast64_t *progress;
} thread_args_t;

static void *search_thread(void *arg) {
    thread_args_t *t = (thread_args_t *)arg;
    BIGNUM  *P   = BN_new();
    BIGNUM  *x   = BN_new();
    BN_CTX  *ctx = BN_CTX_new();
    if (!P || !x || !ctx) goto done;

    uint64_t off  = 2 * t->start + 1;
    uint64_t step = 2 * t->stride;
    uint64_t local = 0;

    while (off < t->window &&
           !atomic_load_explicit(t->global_found, memory_order_relaxed)) {

        int composite = 0;
        for (int i = 0; i < n_small; i++) {
            if ((off % small_primes[i]) == t->sieve_res[i]) {
                composite = 1; break;
            }
        }

        if (!composite) {
            BN_set_word(x, (BN_ULONG)off);
            BN_add(P, t->shifted, x);
            if (BN_is_prime_fasttest_ex(P, MR_ROUNDS, ctx, 1, NULL)) {
                if (!atomic_exchange(t->global_found, 1)) {
                    t->result = BN_dup(P);
                    t->found  = 1;
                }
                break;
            }
        }

        off += step;
        local++;

        if (local % PROGRESS_INTERVAL == 0)
            atomic_fetch_add_explicit(t->progress, PROGRESS_INTERVAL, memory_order_relaxed);
    }

    if (local % PROGRESS_INTERVAL != 0)
        atomic_fetch_add_explicit(t->progress, local % PROGRESS_INTERVAL, memory_order_relaxed);

done:
    BN_free(P); BN_free(x); BN_CTX_free(ctx);
    atomic_fetch_add(t->threads_done, 1);
    return NULL;
}

/* ── Output Helpers ──────────────────────────────────────────────────────── */

static void print_header(void) {
    printf("\033[32m════════════════════════════════════════════════════════════════════════════════\033[0m\n");
}

static void print_footer(void) {
    printf("\033[32m════════════════════════════════════════════════════════════════════════════════\033[0m\n");
}

static void print_box(const char *label, const char *value) {
    printf("\033[32m│\033[0m %-12s \033[36m%s\033[0m\n", label, value);
}

static void die(const char *msg) { 
    fprintf(stderr, "\033[31merror: %s\033[0m\n", msg); 
    exit(1); 
}

static void show_progress(uint64_t done, uint64_t total, int nbytes,
                           double elapsed, double mr_ms) {
    if (total == 0) total = 1;
    double pct = (double)done / (double)total * 100.0;
    if (pct > 100.0) pct = 100.0;

    double rate = (elapsed > 0.01) ? (double)done / elapsed : 0.0;

    int bar = 36;
    int filled = (int)(bar * pct / 100.0);

    fprintf(stderr, "\r  suffix=%-2d bytes [", nbytes);
    for (int i = 0; i < bar; i++) 
        fputc(i < filled ? '#' : '-', stderr);

    fprintf(stderr, "] %5.1f%%  %7.2fM/s", pct, rate / 1e6);

    if (mr_ms > 0 && done > 1000)
        fprintf(stderr, "  %.1fms/MR", mr_ms);

    if (rate > 100 && done > total / 20) {
        double remaining = (double)(total - done) / rate;
        int sec = (int)(remaining + 0.5);
        if (sec < 60)
            fprintf(stderr, "  ETA %ds", sec);
        else
            fprintf(stderr, "  ETA %d:%02d", sec/60, sec%60);
    }

    fflush(stderr);
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static unsigned char *load_file(const char *path, size_t *sz) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); *sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*sz);
    if (b) fread(b, 1, *sz, f);
    fclose(f); return b;
}

static int gzip_data(const unsigned char *in, size_t in_len,
                     unsigned char **out, size_t *out_len) {
    uLongf bound = compressBound(in_len) + 64;
    *out = malloc(bound);
    if (!*out) return 0;
    z_stream zs = {0};
    zs.next_in   = (Bytef *)in;
    zs.avail_in  = (uInt)in_len;
    zs.next_out  = *out;
    zs.avail_out = (uInt)bound;
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED,
                     15+16, 8, Z_DEFAULT_STRATEGY) != Z_OK) { free(*out); return 0; }
    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) { deflateEnd(&zs); free(*out); return 0; }
    *out_len = zs.total_out;
    deflateEnd(&zs);
    return 1;
}

static double bench_mr(const BIGNUM *bn) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *P = BN_dup(bn);
    if (!BN_is_odd(P)) BN_add_word(P, 1);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    BN_is_prime_fasttest_ex(P, 1, ctx, 1, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    BN_free(P); BN_CTX_free(ctx);
    return ((t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)*1e-9)*1000.0 * MR_ROUNDS;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    char *input_file   = NULL;
    char *input_text   = NULL;
    char *output_file  = NULL;
    char *recover_file = NULL;
    int   decimal_mode = 0;
    int   verbose      = 0;
    int   num_threads  = 0;

    static struct option lopts[] = {
        {"file",    required_argument, 0, 'f'},
        {"text",    required_argument, 0, 't'},
        {"output",  required_argument, 0, 'o'},
        {"recover", required_argument, 0, 'r'},
        {"print",   required_argument, 0, 'p'},
        {"threads", required_argument, 0, 'n'},
        {"verbose", no_argument,       0, 'v'},
        {0,0,0,0}
    };
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "f:t:o:r:p:n:v", lopts, &idx)) != -1) {
        switch (opt) {
            case 'f': input_file   = optarg; break;
            case 't': input_text   = optarg; break;
            case 'o': output_file  = optarg; break;
            case 'r': recover_file = optarg; break;
            case 'p': decimal_mode = (strncmp(optarg,"dec",3)==0||strncmp(optarg,"ful",3)==0); break;
            case 'n': num_threads  = atoi(optarg); break;
            case 'v': verbose      = 1; break;
            default:
                fprintf(stderr,
                    "usage: %s -f file | -t \"text\" | -r prime_file\n"
                    "       [-o outfile] [-p decimal] [-n threads] [-v]\n\n"
                    "Encode:  %s -f source.c -o source.prime\n"
                    "Decode:  %s -r source.prime | gunzip > source.c\n",
                    argv[0], argv[0], argv[0]);
                return 1;
        }
    }

    build_sieve();

    if (num_threads <= 0) {
        num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_threads < 1)  num_threads = 4;
        if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    }

    /* RECOVER MODE */
    if (recover_file) {
        size_t fsz;
        unsigned char *buf = load_file(recover_file, &fsz);
        if (!buf) die("cannot open prime file");

        BIGNUM *prime = NULL;
        size_t diglen = strspn((char *)buf, "0123456789\n\r");
        if (diglen == fsz) {
            while (fsz > 0 && (buf[fsz-1]=='\n'||buf[fsz-1]=='\r')) buf[--fsz]='\0';
            BN_dec2bn(&prime, (char *)buf);
        } else {
            prime = BN_bin2bn(buf, (int)fsz, NULL);
        }
        free(buf);
        if (!prime) die("could not parse prime file");

        int nbytes = BN_num_bytes(prime);
        unsigned char *raw = malloc(nbytes);
        if (!raw) die("out of memory");
        BN_bn2bin(prime, raw);
        BN_free(prime);

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) die("cannot write output");
            fwrite(raw, 1, nbytes, f);
            fclose(f);
            fprintf(stderr, "Written %d bytes to '%s'\n", nbytes, output_file);
            fprintf(stderr, "Run: gunzip '%s'\n", output_file);
        } else {
            fwrite(raw, 1, nbytes, stdout);
        }
        free(raw);
        return 0;
    }

    /* ENCODE MODE */
    if (!input_file && !input_text)
        die("provide -f file or -t \"text\"");

    unsigned char *data = NULL;
    size_t         data_len = 0;

    if (input_text) {
        data_len = strlen(input_text);
        data = malloc(data_len);
        if (!data) die("out of memory");
        memcpy(data, input_text, data_len);
    } else {
        data = load_file(input_file, &data_len);
        if (!data) die("cannot read input file");
    }

    /* Header */
    print_header();
    printf("\033[32m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[32m║\033[0m               \033[1;36mIllegal Prime Encoder\033[0m  —  Phil Carmody Method               \033[32m║\033[0m\n");
    printf("\033[32m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m\n\n");

    /* Info section - clean alignment */
    printf("\033[32m│\033[0m Input        \033[36m%zu bytes\033[0m\n", data_len);

    unsigned char *gz    = NULL;
    size_t         gz_len = 0;
    if (!gzip_data(data, data_len, &gz, &gz_len)) { 
        free(data); die("gzip failed"); 
    }
    free(data);

    printf("\033[32m│\033[0m Gzipped      \033[36m%zu bytes\033[0m\n", gz_len);

    BIGNUM *K       = BN_bin2bn(gz, (int)gz_len, NULL);
    BIGNUM *shifted = BN_new();
    BIGNUM *scale   = BN_new();
    BIGNUM *result  = NULL;

    char info_buf[80];
    snprintf(info_buf, sizeof(info_buf), "%d bits (~%d digits)", 
             BN_num_bits(K), (BN_num_bits(K) * 3010) / 10000);
    print_box("Bignum", info_buf);

    snprintf(info_buf, sizeof(info_buf), "%d", num_threads);
    print_box("Threads", info_buf);

    print_footer();
    printf("\n");

    fprintf(stderr, "Benchmarking MR cost... ");
    fflush(stderr);

    {
        BN_CTX *ctx = BN_CTX_new();
        BN_set_word(scale, 256);
        BN_mul(shifted, K, scale, ctx);
        BN_CTX_free(ctx);
    }
    double mr_ms = bench_mr(shifted);
    fprintf(stderr, "~%.1f ms/candidate\n\n", mr_ms);

    int found = 0;

    for (int n = 1; n <= MAX_SUFFIX_BYTES && !found; n++) {
        BN_CTX *ctx = BN_CTX_new();
        BN_set_word(scale, 1);
        for (int i = 0; i < n; i++) BN_mul_word(scale, 256);
        BN_mul(shifted, K, scale, ctx);
        BN_CTX_free(ctx);

        uint64_t window;
        if (n >= 8) window = UINT64_MAX;
        else { window = 1; for (int i = 0; i < n; i++) window *= 256; }

        uint32_t *sieve_res = build_residues(shifted);
        if (!sieve_res) die("out of memory");

        printf("\033[32m┌─\033[0m Trying %d-byte suffix ", n);
        printf("\033[33m(window = %llu)\033[0m\n", (unsigned long long)window);

        pthread_t            threads[MAX_THREADS];
        thread_args_t        args[MAX_THREADS];
        atomic_int           gfound       = 0;
        atomic_int           threads_done = 0;
        atomic_uint_fast64_t prog         = 0;

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        for (int i = 0; i < num_threads; i++) {
            args[i].shifted      = shifted;
            args[i].sieve_res    = sieve_res;
            args[i].start        = (uint64_t)i;
            args[i].stride       = (uint64_t)num_threads;
            args[i].window       = window;
            args[i].found        = 0;
            args[i].result       = NULL;
            args[i].global_found = &gfound;
            args[i].threads_done = &threads_done;
            args[i].progress     = &prog;
            pthread_create(&threads[i], NULL, search_thread, &args[i]);
        }

        while (!atomic_load_explicit(&gfound, memory_order_relaxed) &&
               atomic_load_explicit(&threads_done, memory_order_relaxed) < num_threads) {

            uint64_t current = atomic_load_explicit(&prog, memory_order_relaxed);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
            uint64_t total_candidates = (window + 1) / 2;

            show_progress(current, total_candidates, n, el, mr_ms);
            usleep(50000);
        }

        {
            uint64_t final_prog = atomic_load_explicit(&prog, memory_order_relaxed);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double final_el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
            uint64_t total_candidates = (window + 1) / 2;
            show_progress(final_prog, total_candidates, n, final_el, mr_ms);
            fprintf(stderr, "\n");
        }

        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
            if (args[i].found && !result) { 
                result = args[i].result; 
                found = 1; 
            }
            else if (args[i].result) BN_free(args[i].result);
        }
        free(sieve_res);

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)*1e-9;
        uint64_t tested = atomic_load(&prog);

        if (found) {
            printf("\033[32m└─\033[0m ");
            printf("\033[1;32m✓ Prime found!\033[0m  (%.3fs, %llu candidates sieved)\n\n", 
                   elapsed, (unsigned long long)tested);
        } else {
            printf("\033[32m└─\033[0m No prime with %d-byte suffix, trying longer...\n", n);
        }
    }

        if (!found) {
        fprintf(stderr, "No prime found up to %d-byte suffix.\n", MAX_SUFFIX_BYTES);
        goto cleanup;
    }

    /* ── SUCCESS BOX ─────────────────────────────────────────────────────── */
    print_header();
    printf("\033[32m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[32m║\033[0m                        \033[1;32mSUCCESS: Prime Found!\033[0m                         \033[32m║\033[0m\n");
    printf("\033[32m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m\n\n");

    /* Print prime to screen when -p full is used */
    if (decimal_mode) {
        char *dec = BN_bn2dec(result);
        if (dec) {
            printf("\033[36m%s\033[0m\n\n", dec);
            OPENSSL_free(dec);
        }
    }

    snprintf(info_buf, sizeof(info_buf), "%d bits (%d bytes)", 
             BN_num_bits(result), BN_num_bytes(result));
    print_box("Prime size", info_buf);

    /* ── FILE SAVING (Fixed) ─────────────────────────────────────────────── */
    if (output_file) {
        FILE *f = fopen(output_file, "wb");
        if (!f) {
            fprintf(stderr, "\033[31mWarning: cannot write '%s'\033[0m\n", output_file);
        } else {
            if (decimal_mode) {
                char *dec = BN_bn2dec(result);
                if (dec) {
                    fputs(dec, f);
                    fputc('\n', f);
                    OPENSSL_free(dec);
                }
                print_box("Saved to", output_file);
                print_box("Format", "Decimal text");
            } else {
                int len = BN_num_bytes(result);
                unsigned char *raw = malloc(len);
                if (raw) {
                    BN_bn2bin(result, raw);
                    fwrite(raw, 1, len, f);
                    free(raw);
                }
                print_box("Saved to", output_file);
                print_box("Format", "Raw binary");
            }
            fclose(f);
        }
    } else {
        /* No output file → print to stdout if not already printed */
        if (!decimal_mode) {
            BN_print_fp(stdout, result);
            printf("\n");
        }
    }

    printf("\033[32m│\033[0m\n");
    printf("\033[32m│\033[0m \033[1mRecovery command:\033[0m\n");
    printf("\033[32m│\033[0m   \033[36m%s -r \"%s\" | gunzip > recovered.original\033[0m\n",
           argv[0], output_file ? output_file : "<prime_file>");

    print_footer();
    printf("\n");

    /* Verification */
    {
        int plen = BN_num_bytes(result);
        unsigned char *raw = malloc(plen + 1);
        if (raw) {
            BN_bn2bin(result, raw);

            z_stream zs = {0};
            size_t   decomp_max = data_len * 4 + 65536;
            unsigned char *decomp = malloc(decomp_max);

            zs.next_in   = raw;
            zs.avail_in  = plen;
            zs.next_out  = decomp;
            zs.avail_out = (uInt)decomp_max;

            int ok = (inflateInit2(&zs, 15+16) == Z_OK &&
                      inflate(&zs, Z_FINISH) == Z_STREAM_END);
            inflateEnd(&zs);

            if (ok) {
                fprintf(stderr, "Verification: OK  (%lu bytes recovered)\n",
                        (unsigned long)zs.total_out);
            } else {
                fprintf(stderr, "Verification: FAILED\n");
            }
            free(raw);
            free(decomp);
        }
    }

cleanup:
    free(gz);
    BN_free(K);
    BN_free(shifted);
    BN_free(scale);
    BN_free(result);
    return found ? 0 : 1;
}
