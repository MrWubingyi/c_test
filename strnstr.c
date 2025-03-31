#include <ctype.h>
#include <immintrin.h> // AVX2
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <immintrin.h>
#include <stddef.h>
#include <string.h>
#include <time.h> // 新增时间测量头文件

#include <smmintrin.h> // SSE4.1
#include <stddef.h>
#include <string.h>

const char *optimized_sse41_strnstr(const char *data, size_t len,
                                    const char *target) {
  const size_t target_len = strlen(target);
  if (target_len == 0 || len < target_len || target_len > 16)
    return NULL;

  // 预加载首尾字符（双检测策略）
  const char first_char = target[0];
  const char last_char = target[target_len - 1];
  const __m128i first_vec = _mm_set1_epi8(first_char);
  const __m128i last_vec = _mm_set1_epi8(last_char);

  // SIMD寄存器复用配置
  const size_t step_size = 32; // 同时处理两个16字节块
  const size_t safe_end = len - target_len;
  size_t prefetch_offset = 64; // 预取提前量

  for (size_t i = 0; i <= safe_end;) {
    // 内存预取优化（提前预取后续数据）
    if (i + prefetch_offset < len) {
      _mm_prefetch(data + i + prefetch_offset, _MM_HINT_T0);
    }

    // SIMD寄存器复用：同时加载两个16字节块
    __m128i chunk1, chunk2;
    if (i + step_size <= len) {
      chunk1 = _mm_loadu_si128((__m128i *)(data + i));
      chunk2 = _mm_loadu_si128((__m128i *)(data + i + 16));
    } else {
      // 处理剩余不足32字节的情况
      char buffer1[16] = {0}, buffer2[16] = {0};
      const size_t remain = len - i;
      memcpy(buffer1, data + i, remain > 16 ? 16 : remain);
      if (remain > 16) {
        memcpy(buffer2, data + i + 16, remain - 16);
      }
      chunk1 = _mm_loadu_si128((__m128i *)buffer1);
      chunk2 = _mm_loadu_si128((__m128i *)buffer2);
    }

    // 双块并行匹配首字符
    const __m128i cmp1 = _mm_cmpeq_epi8(chunk1, first_vec);
    const __m128i cmp2 = _mm_cmpeq_epi8(chunk2, first_vec);
    int mask = _mm_movemask_epi8(cmp1) | (_mm_movemask_epi8(cmp2) << 16);

    while (mask) {
      const int lsb = __builtin_ctz(mask);
      const size_t pos = i + (lsb % 16) + ((lsb >= 16) ? 16 : 0);

      // 边界检查
      if (pos > safe_end) {
        mask &= ~(1 << lsb);
        continue;
      }

      // 双检测策略：验证首尾字符
      if (data[pos + target_len - 1] == last_char) {
        if (memcmp(data + pos, target, target_len) == 0) {
          return data + pos;
        }
      }

      mask &= mask - 1;
    }

    // 动态步进调整
    const size_t next_block = (i % step_size == 0) ? step_size : 16;
    i += (mask == 0) ? next_block : 1;
  }
  return NULL;
}

const char *sse41_strnstr(const char *data, size_t len, const char *target) {
  // printf("sse4");
  size_t target_len = strlen(target);
  if (target_len == 0 || len < target_len || target_len > 16)
    return NULL;

  // 加载目标字符串首字符
  const char first_char = target[0];
  const __m128i first_char_vec = _mm_set1_epi8(first_char);

  // 预计算末尾安全位置
  const size_t safe_end = len - target_len;

  for (size_t i = 0; i <= safe_end;) {
    // 加载 16 字节数据块（带边界保护）
    __m128i chunk;
    if (i + 16 <= len) {
      chunk = _mm_loadu_si128((__m128i *)(data + i));
    } else {
      char buffer[16] = {0};
      memcpy(buffer, data + i, len - i);
      chunk = _mm_loadu_si128((__m128i *)buffer);
    }

    // 查找首字符匹配位置
    const __m128i cmp = _mm_cmpeq_epi8(chunk, first_char_vec);
    int mask = _mm_movemask_epi8(cmp);

    // 快速跳过无匹配的情况
    if (mask == 0) {
      i += 16;
      continue;
    }

    // 处理所有匹配位置
    while (mask) {
      const int lsb = __builtin_ctz(mask);
      const size_t pos = i + lsb;

      // 有效性检查
      if (pos > safe_end) {
        mask &= ~(1 << lsb);
        continue;
      }

      // 完整字符串比较
      if (memcmp(data + pos, target, target_len) == 0) {
        return data + pos;
      }

      mask &= mask - 1; // 清除最低有效位
    }

    // 步进优化：直接跳到下一个未检查的位置
    i += (i % 16 == 0) ? 16 : 1;
  }
  return NULL;
}

const char *simd_strnstr_avx2(const char *data, size_t len,
                              const char *target) {
  size_t target_len = strlen(target);
  if (target_len == 0 || len < target_len || target_len > 32)
    return NULL;
  // printf("avx2");

  // 仅加载目标字符串的第一个字符用于 SIMD 扫描
  char first_char = target[0];
  __m256i first_char_vec = _mm256_set1_epi8(first_char);

  for (size_t i = 0; i <= len - target_len; ++i) {
    // 加载 32 字节数据块（边界安全）
    __m256i chunk;
    if (i + 32 <= len) {
      chunk = _mm256_loadu_si256((__m256i *)(data + i));
    } else {
      char buffer[32] = {0};
      memcpy(buffer, data + i, len - i);
      chunk = _mm256_loadu_si256((__m256i *)buffer);
    }

    // 查找首字符匹配位置
    __m256i cmp = _mm256_cmpeq_epi8(chunk, first_char_vec);
    int mask = _mm256_movemask_epi8(cmp);

    while (mask) {
      int pos = __builtin_ctz(mask);
      size_t candidate = i + pos;

      // 验证后续字符
      if (candidate + target_len <= len &&
          memcmp(data + candidate, target, target_len) == 0) {
        return data + candidate;
      }

      mask &= mask - 1; // 清除最低有效位
    }
  }
  return NULL;
}
char *dpi_strncasestr_kmp(const char *haystack, int haystack_len,
                          const char *needle) {
  int len_haystack = haystack_len;
  int len_needle = strlen(needle);

  if (len_needle > len_haystack) {
    return NULL;
  }

  int i = 0, j = -1;
  int next[len_needle];
  next[0] = -1;

  while (i < len_needle - 1) {
    if (j == -1 || tolower(needle[i]) == tolower(needle[j])) {
      ++i;
      ++j;
      next[i] = (tolower(needle[i]) != tolower(needle[j])) ? j : next[j];
    } else {
      j = next[j];
    }
  }

  i = j = 0;
  while (i < len_haystack && j < len_needle) {
    if (j == -1 || tolower(haystack[i]) == tolower(needle[j])) {
      ++i;
      ++j;
    } else {
      j = next[j];
    }
  }

  if (j == len_needle) {
    return (char *)(haystack + i - j);
  } else {
    return NULL;
  }
}

const char *dpi_strnstr_kmp(const char *haystack, int haystack_len,
                            const char *needle) {
  int len_haystack = haystack_len;
  int len_needle = strlen(needle);
  // printf("kmp");./s

  if (len_needle > len_haystack) {
    return NULL;
  }

  int i = 0, j = -1;
  int next[len_needle];
  next[0] = -1;

  while (i < len_needle - 1) {
    if (j == -1 || needle[i] == needle[j]) {
      ++i;
      ++j;
      next[i] = (needle[i] != needle[j]) ? j : next[j];
    } else {
      j = next[j];
    }
  }

  i = j = 0;
  while (i < len_haystack && j < len_needle) {
    if (j == -1 || haystack[i] == needle[j]) {
      ++i;
      ++j;
    } else {
      j = next[j];
    }
  }

  if (j == len_needle) {
    return (char *)(haystack + i - j);
  } else {
    return NULL;
  }
}

// 根据模式长度自动选择最优算法
#include <stddef.h>
#include <string.h>

// 添加 CPUID 头文件（GCC/MSVC 兼容）
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#endif

// 平台特征检测宏
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
#define X86_ARCH 1
#else
#define X86_ARCH 0
#endif

// 编译器指令集支持检测
#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX2__))
#define COMPILER_AVX2 1
#else
#define COMPILER_AVX2 0
#endif

#if defined(__SSE4_1__) || (defined(_MSC_VER) && defined(__SSE4_1__))
#define COMPILER_SSE41 1
#else
#define COMPILER_SSE41 0
#endif

struct CpuFeatures {
  int avx2_supported;
  int sse41_supported;
};

// 修正后的 CPU 特征初始化函数
static inline void init_cpu_features(struct CpuFeatures *features) {
  features->avx2_supported = 0;
  features->sse41_supported = 0;

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) ||            \
    defined(_M_X64)
  unsigned int regs[4] = {0};

// 检测 SSE4.1
#if defined(__GNUC__)
  __cpuid_count(1, 0, regs[0], regs[1], regs[2], regs[3]);
#elif defined(_MSC_VER)
  __cpuid(regs, 1);
#endif
  features->sse41_supported = (regs[2] & (1 << 19)) ? 1 : 0;

// 检测 AVX2
#if defined(__GNUC__)
  __cpuid_count(7, 0, regs[0], regs[1], regs[2], regs[3]);
#elif defined(_MSC_VER)
  __cpuidex(regs, 7, 0);
#endif
  features->avx2_supported = (regs[1] & (1 << 5)) ? 1 : 0;
#endif
}

// 修正后的特征缓存实现（使用静态初始化）
static struct CpuFeatures g_cpu_features = {0};
static int g_initialized = 0;

static inline struct CpuFeatures get_cpu_features() {
  if (!g_initialized) {
    init_cpu_features(&g_cpu_features);
    g_initialized = 1;
  }
  return g_cpu_features;
}

#include <string.h>
#include <immintrin.h>

const char *sse41_strncasestr(const char *haystack, size_t len,
                              const char *needle) {
    const size_t needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    if (needle_len > 16) return NULL;

    // 加载并处理needle（转换为小写且清除高位）
    __m128i n = _mm_loadu_si128((const __m128i *)needle);
    n = _mm_and_si128(_mm_or_si128(n, _mm_set1_epi8(0x20)), 
                     _mm_set1_epi8(0x7F));

    // 创建正确的比较掩码（前needle_len字节参与比较）
    __m128i mask = _mm_cmplt_epi8(
        _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),
        _mm_set1_epi8(needle_len)
    );

    // 主搜索循环
    for (size_t i = 0; i + 16 <= len; ++i) {
        __m128i h = _mm_loadu_si128((const __m128i *)(haystack + i));
        h = _mm_and_si128(_mm_or_si128(h, _mm_set1_epi8(0x20)), 
                         _mm_set1_epi8(0x7F));

        __m128i cmp = _mm_cmpeq_epi8(h, n);
        int bits = _mm_movemask_epi8(_mm_and_si128(cmp, mask));

        if (bits == ((1 << needle_len) - 1)) {
            if (i + needle_len > len) break;
            if (memcmp(haystack + i, needle, needle_len) == 0)
                return haystack + i;
        }
    }

    // 处理末尾剩余部分
    if (len >= needle_len) {
        const char *end = haystack + len - needle_len;
        for (const char *p = haystack; p <= end; ++p) {
            if (strncasecmp(p, needle, needle_len) == 0)
                return p;
        }
    }
    return NULL;
}

#include <string.h>
#include <immintrin.h>

const char *simd_strncasestr_avx2(const char *haystack, size_t len,
                                  const char *needle) {
    const size_t needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    if (needle_len > 32) return NULL;  // AVX2寄存器最大处理32字节

    // 加载needle并转换为小写，同时清除非ASCII高位
    __m256i n = _mm256_loadu_si256((const __m256i *)needle);
    n = _mm256_and_si256(_mm256_or_si256(n, _mm256_set1_epi8(0x20)),
                        _mm256_set1_epi8(0x7F));

    // 创建有效位掩码（前needle_len字节参与比较）
    const __m256i mask = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(needle_len),
        _mm256_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                         16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31)
    );

    // 主搜索循环（每次处理32字节块）
    for (size_t i = 0; i + 32 <= len; ++i) {
         __m256i h = _mm256_loadu_si256((const __m256i *)(haystack + i));
        h = _mm256_and_si256(_mm256_or_si256(h, _mm256_set1_epi8(0x20)),
                            _mm256_set1_epi8(0x7F));

        // 应用掩码进行比较
        __m256i cmp = _mm256_and_si256(_mm256_cmpeq_epi8(h, n), mask);
        int bits = _mm256_movemask_epi8(cmp);

        // 检查完整匹配
        if (bits == ((1 << needle_len) - 1)) {
            // 验证实际内容匹配
            if (i + needle_len > len) break;
            if (strncasecmp(haystack + i, needle, needle_len) == 0)
                return haystack + i;
        }
    }

    // 处理剩余部分（非SIMD方式）
    const size_t remaining = len % 32;
    const char *end = haystack + len - needle_len;
    for (const char *p = haystack + len - remaining; p <= end; ++p) {
        if (strncasecmp(p, needle, needle_len) == 0)
            return p;
    }

    return NULL;
}


// 算法选择逻辑
const char *hybrid_strnstr(const char *data, size_t len, const char *target) {
  const size_t target_len = strlen(target);
  const struct CpuFeatures features = get_cpu_features();

  // 基础校验
  if (target_len == 0)
    return data;
  if (len < target_len)
    return NULL;

  // 根据长度和硬件支持选择算法
  if (target_len <= 16) {
#if COMPILER_SSE41 && X86_ARCH
    if (features.sse41_supported) {
      return sse41_strnstr(data, len, target);
    }
#endif
    // 回退到 KMP
    return dpi_strnstr_kmp(data, len, target);
  } else if (target_len <= 64) {
#if COMPILER_AVX2 && X86_ARCH
    if (features.avx2_supported) {
      return simd_strnstr_avx2(data, len, target);
    }
#endif
    // 回退到 SSE4.1 或 KMP
#if COMPILER_SSE41 && X86_ARCH
    if (features.sse41_supported) {
      return sse41_strnstr(data, len, target);
    }
#endif
    return dpi_strnstr_kmp(data, len, target);
  } else {
    return dpi_strnstr_kmp(data, len, target);
  }
}

const char *hybrid_strncasestr(const char *data, size_t len,
                               const char *target) {
  const size_t target_len = strlen(target);
  const struct CpuFeatures features = get_cpu_features();

  if (target_len == 0)
    return data;
  if (len < target_len)
    return NULL;

  // 添加大小写不敏感标识
  const uint8_t case_insensitive = 1 /* 根据实际情况判断 */;

  if (target_len <= 16) {
#if COMPILER_SSE41 && X86_ARCH
    if (features.sse41_supported && case_insensitive) {
      return sse41_strncasestr(data, len, target);
    }
#endif
    return dpi_strncasestr_kmp(data, len, target);
  } else if (target_len <= 64) {
#if COMPILER_AVX2 && X86_ARCH
    if (features.avx2_supported && case_insensitive) {
      return simd_strncasestr_avx2(data, len, target);
    }
#endif
#if COMPILER_SSE41 && X86_ARCH
    if (features.sse41_supported && case_insensitive) {
      return sse41_strncasestr(data, len, target);
    }
#endif
    return dpi_strncasestr_kmp(data, len, target);
  } else {
    return dpi_strncasestr_kmp(data, len, target);
  }
}

#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
char *strnstr(const char *s1, const char *s2, size_t len) {
  size_t l2;

  l2 = strlen(s2);
  if (!l2)
    return (char *)s1;
  while (len >= l2) {
    len--;
    if (!memcmp(s1, s2, l2))
      return (char *)s1;
    s1++;
  }
  return NULL;
}
// 性能测试框架
typedef const char *(*search_func)(const char *, size_t, const char *);

long long benchmark(search_func func, const char *data, size_t len,
                    const char *target, int warmup_rounds, int test_rounds) {
  struct timespec start, end;
  long long total_ns = 0;
  // const char *real_result = dpi_strncasestr_kmp(data, len, target);
  long long pos = 0;
  // 预热阶段
  for (int i = 0; i < warmup_rounds; ++i) {
    const char *result = func(data, len, target);
    // if (result) {
    //   pos += result - real_result;
    // }
  }
  // printf("bench result = %lld\n", pos);
  // 正式测试
  for (int i = 0; i < test_rounds; ++i) {
    timespec_get(&start, TIME_UTC);
    func(data, len, target);
    timespec_get(&end, TIME_UTC);

    long long ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
                   (end.tv_nsec - start.tv_nsec);
    total_ns += ns;
  }

  return total_ns / test_rounds; // 返回平均耗时
}

void *bench(char *buffer, int bytes_read, int warmup, int runs, char *target) {

  // 执行基准测试
  long long hybrid_ns =
      benchmark(hybrid_strnstr, buffer, bytes_read, target, warmup, runs);
  long long avx2_ns =
      benchmark(simd_strnstr_avx2, buffer, bytes_read, target, warmup, runs);
  long long sse41_ns =
      benchmark(sse41_strnstr, buffer, bytes_read, target, warmup, runs);
  long long kmp_ns =
      benchmark(dpi_strnstr_kmp, buffer, bytes_read, target, warmup, runs);
  long long opt_sse4_ns = benchmark(optimized_sse41_strnstr, buffer, bytes_read,
                                    target, warmup, runs);
  // 输出结果
  printf("\nstrnstr性能测试结果 (平均 %d 次运行):\n", runs);
  printf("├─ Hybrid     算法: %10.3f μs\n", hybrid_ns / 1000.0);
  printf("├─ AVX2       算法: %10.3f μs\n", avx2_ns / 1000.0);
  printf("├─ SSE4.1     算法: %10.3f μs\n", sse41_ns / 1000.0);
  printf("├─ OPT_SSE4.1 算法: %10.3f μs\n", opt_sse4_ns / 1000.0);
  printf("└─ KMP        算法: %10.3f μs\n", kmp_ns / 1000.0);

  // 执行基准测试
  hybrid_ns =
      benchmark(hybrid_strncasestr, buffer, bytes_read, target, warmup, runs);
  avx2_ns = benchmark(simd_strncasestr_avx2, buffer, bytes_read, target, warmup,
                      runs);
  sse41_ns =
      benchmark(sse41_strncasestr, buffer, bytes_read, target, warmup, runs);
  kmp_ns =
      benchmark(dpi_strncasestr_kmp, buffer, bytes_read, target, warmup, runs);

  // 输出结果
  printf("\nstrncase性能测试结果 (平均 %d 次运行):\n", runs);
  printf("├─ Hybrid     算法: %10.3f μs\n", hybrid_ns / 1000.0);
  printf("├─ AVX2       算法: %10.3f μs\n", avx2_ns / 1000.0);
  printf("├─ SSE4.1     算法: %10.3f μs\n", sse41_ns / 1000.0);
  printf("└─ KMP        算法: %10.3f μs\n", kmp_ns / 1000.0);
}
int main() {
  const int warmup = 1000;
  const int runs = 1000000;

  // 加载测试数据
  FILE *file = fopen("http.txt", "rb");
  if (!file) {
    perror("无法打开文件");
    return 1;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  rewind(file);

  char *buffer = malloc(file_size + 1);
  if (!buffer) {
    fclose(file);
    perror("内存分配失败");
    return 1;
  }

  size_t bytes_read = fread(buffer, 1, file_size, file);
  buffer[bytes_read] = '\0';
  fclose(file);
  const char *target = "022D831447EB0A2052CA6F5AA4F33732CF013C23830BBC604E444C779A826E2F";

  bench(buffer, bytes_read, warmup, runs, target);
    const char *result = simd_strncasestr_avx2(buffer, bytes_read, target);

    if (result) {
        printf("找到目标字符串 '%s' 在位置 %ld\nbuffer = %s\n", target, result - buffer,buffer);
    } else {
        printf("未找到目标字符串 '%s'\n", target);
    }
  free(buffer);
  return 0;
}
