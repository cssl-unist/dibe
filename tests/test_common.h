/*
 * test_common.h — Minimal unit test framework (no external dependencies)
 *
 * Usage:
 *   #include "test_common.h"
 *
 *   TEST(my_test) {
 *       ASSERT_TRUE(1 == 1);
 *       ASSERT_EQ(2, 2);
 *   }
 *
 *   int main() {
 *       RUN_TEST(my_test);
 *       return test_report();
 *   }
 */
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <string.h>

static int g_test_pass = 0;
static int g_test_fail = 0;
static int g_test_cur_fail = 0;

#define TEST(name) static void test_##name(void)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "  FAIL %s:%d: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #expr); \
        g_test_fail++; g_test_cur_fail++; \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "  FAIL %s:%d: ASSERT_EQ(%s, %s) -> %lld != %lld\n", \
                __FILE__, __LINE__, #a, #b, _a, _b); \
        g_test_fail++; g_test_cur_fail++; \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a == _b) { \
        fprintf(stderr, "  FAIL %s:%d: ASSERT_NE(%s, %s) -> both %lld\n", \
                __FILE__, __LINE__, #a, #b, _a); \
        g_test_fail++; g_test_cur_fail++; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    const char *_a = (a), *_b = (b); \
    if (strcmp(_a, _b) != 0) { \
        fprintf(stderr, "  FAIL %s:%d: ASSERT_STR_EQ(%s, %s) -> \"%s\" != \"%s\"\n", \
                __FILE__, __LINE__, #a, #b, _a, _b); \
        g_test_fail++; g_test_cur_fail++; \
    } \
} while(0)

#define RUN_TEST(name) do { \
    g_test_cur_fail = 0; \
    fprintf(stderr, "  %-40s ", #name); \
    test_##name(); \
    if (g_test_cur_fail == 0) { \
        g_test_pass++; \
        fprintf(stderr, "PASS\n"); \
    } else { \
        fprintf(stderr, "  ^^^ %d assertion(s) failed\n", g_test_cur_fail); \
    } \
} while(0)

static int test_report(void) {
    fprintf(stderr, "\n  %d passed, %d failed\n",
            g_test_pass, g_test_fail > 0 ? 1 : 0);
    return g_test_fail > 0 ? 1 : 0;
}

#endif /* TEST_COMMON_H */
