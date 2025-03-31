#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define get_uint32_ntohl(X, O)                                                 \
  (ntohl(*(const uint32_t *)(((const uint8_t *)X) + O)))
#define COMMON_SOME_TYPE 64

typedef struct _dpi_file_table_type_t {
  uint32_t code;
  const char file_type[32];
} dpi_file_table_type;

static dpi_file_table_type dpi_file_table[] = {
    {0x255044, "pdf"}, {0x526563, "eml"}, {0xD0CF11, "ppt"},
    {0x4D5AEE, "com"}, {0xE93B03, "com"}, {0x4D5A90, "dll"},
    {0x424d3e, "bmp"}, {0x49492a, "tif"}, {0x384250, "psd"},
    {0xc5d0d3, "eps"}, {0x0a0501, "pcs"}, {0x89504e, "png"},
    {0x060500, "raw"}, {0x000002, "tga"}, {0x60ea27, "arj"},
    {0x526172, "rar"}, {0x504b03, "zip"}, {0x495363, "cab"},
    {0x1f9d8c, "z"},   {0x524946, "wav"}, {0x435753, "swf"},
    {0x3026b2, "wmv"}, {0x3026b2, "wma"}, {0x2e524d, "rm"},
    {0x00000f, "mov"}, {0x000077, "mov"}, {0x000001, "mpa"},
    {0xfffb50, "mp3"}, {0x234558, "m3u"}, {0x3C2144, "html"},
    {0xfffe3c, "xsl"}, {0x3c3f78, "xml"}, {0x3c3f78, "msc"},
    {0x4c0000, "lnk"}, {0x495453, "chm"}, {0x805343, "scm"},
    {0xd0cf11, "xls"}, {0x31be00, "wri"}, {0x00ffff, "mdf"},
    {0x4d4544, "mds"}, {0x5b436c, "ccd"}, {0x00ffff, "img"},
    {0xffffff, "sub"}, {0x17a150, "pcb"}, {0x2a5052, "eco"},
    {0x526563, "ppc"}, {0x000100, "ddb"}, {0x42494c, "ldb"},
    {0x2a7665, "sch"}, {0x2a2420, "lib"}, {0x434841, "fnt"},
    {0x7b5c72, "rtf"}, {0x7b5072, "gtd"}, {0x234445, "prg"},
    {0x000007, "pjt"}, {0x202020, "bas"}, {0x000002, "tag"},
    {0x4d5a50, "dpl"}, {0x3f5f03, "hlp"}, {0x3f5f03, "lhp"},
    {0xc22020, "nls"}, {0x5b5769, "cpx"}, {0x4d5a16, "drv"},
    {0x5b4144, "pbk"}, {0x24536f, "pll"}, {0x4e4553, "nes"},
    {0x87f53e, "gbc"}, {0x00ffff, "smd"}, {0x584245, "xbe"},
    {0x005001, "xmv"}, {0x000100, "ttf"}, {0x484802, "pdg"},
    {0x000100, "tst"}, {0x414331, "dwg"}, {0xd0cf11, "max"},
    {0x777867, "wxgf"}};

#define MAX_KMP_SIZE 2000

void Nextval(char T[], int lenT, int *next) {
  int k = -1;
  int j = 0;
  next[0] = -1;
  while (j < lenT) {
    if (k == -1 || T[j] == T[k]) {
      j++;
      k++;
      if (T[j] != T[k]) {
        next[j] = k;
      } else {
        next[j] = next[k];
      }
    } else {
      k = next[k];
    }
  }
}

int KMP(char S[], int S_len, char T[], int lenT) {
  int i = 0, j = 0, lenS;
  lenS = S_len;
  int next[MAX_KMP_SIZE];

  Nextval(T, lenT, next);
  while (i < lenS && j < lenT) {
    if (j == -1 || S[i] == T[j]) {
      i++;
      j++;
    } else {
      j = next[j];
    }
  }
  if (j == lenT) {
    return i - j;
  } else {
    return -1;
  }
}

// AC自动机节点结构
#define ASCII_SIZE 256
typedef struct ac_node {
  struct ac_node *children[ASCII_SIZE];
  struct ac_node *fail;
  char *file_type;
} ac_node;

// 简单队列实现
typedef struct queue_node {
  ac_node *data;
  struct queue_node *next;
} queue_node;

typedef struct {
  queue_node *front;
  queue_node *rear;
} queue;

void enqueue(queue *q, ac_node *data) {
  queue_node *new_node = (queue_node *)malloc(sizeof(queue_node));
  new_node->data = data;
  new_node->next = NULL;

  if (q->rear) {
    q->rear->next = new_node;
  }
  q->rear = new_node;

  if (!q->front) {
    q->front = q->rear;
  }
}

ac_node *dequeue(queue *q) {
  if (!q->front)
    return NULL;

  queue_node *temp = q->front;
  ac_node *data = temp->data;

  q->front = q->front->next;
  if (!q->front) {
    q->rear = NULL;
  }

  free(temp);
  return data;
}

int is_empty(queue *q) { return q->front == NULL; }

ac_node *create_node() {
  ac_node *node = (ac_node *)calloc(1, sizeof(ac_node));
  node->fail = NULL;
  node->file_type = NULL;
  return node;
}

void ac_insert(ac_node *root, const unsigned char *pattern, int len,
               const char *file_type) {
  ac_node *curr = root;
  for (int i = 0; i < len; i++) {
    int index = pattern[i];
    if (!curr->children[index]) {
      curr->children[index] = create_node();
    }
    curr = curr->children[index];
  }
  curr->file_type = strdup(file_type);
}

void build_failure_links(ac_node *root) {
  queue q = {NULL, NULL};
  enqueue(&q, root);
  root->fail = NULL;

  while (!is_empty(&q)) {
    ac_node *curr = dequeue(&q);

    for (int i = 0; i < ASCII_SIZE; i++) {
      if (!curr->children[i])
        continue;

      ac_node *fail = curr->fail;
      while (fail && !fail->children[i]) {
        fail = fail->fail;
      }
      curr->children[i]->fail = fail ? fail->children[i] : root;

      enqueue(&q, curr->children[i]);
    }
  }
}

int ac_search(ac_node *root, const char *text, int len, char *result) {
  ac_node *curr = root;
  for (int i = 0; i < len; i++) {
    int index = (unsigned char)text[i];
    while (curr && !curr->children[index]) {
      curr = curr->fail;
    }
    curr = curr ? curr->children[index] : root;

    ac_node *tmp = curr;
    while (tmp) {
      if (tmp->file_type) {
        strncpy(result, tmp->file_type, 4);
        return 1;
      }
      tmp = tmp->fail;
    }
  }
  return 0;
}
static ac_node *office_patterns = NULL;
static pthread_once_t office_once = PTHREAD_ONCE_INIT;

static void init_office_patterns() {
    office_patterns = create_node();
      // 认为是office 2007版本的数据
      // Office二进制模式
      const unsigned char doc_pattern[] = {0x57, 0x6F, 0x72, 0x64, 0x44, 0x6F,
                                           0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74};
      const unsigned char doc_wide_pattern[] = {
          0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00,
          0x44, 0x00, 0x6F, 0x00, 0x63, 0x00, 0x75, 0x00,
          0x6D, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74};
      ac_insert(office_patterns, doc_pattern, sizeof(doc_pattern), "doc");
      ac_insert(office_patterns, doc_wide_pattern, sizeof(doc_wide_pattern),
                "doc");

      const unsigned char xls_pattern[] = {0x4D, 0x69, 0x63, 0x72, 0x6F,
                                           0x73, 0x6F, 0x66, 0x74, 0x20,
                                           0x45, 0x78, 0x63, 0x65, 0x6C};

      const unsigned char xls_wide_pattern[] = {
          0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00,
          0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00,
          0x45, 0x00, 0x78, 0x00, 0x63, 0x00, 0x65, 0x00, 0x6C, 0x00};
      ac_insert(office_patterns, xls_pattern, sizeof(xls_pattern), "xls");
      ac_insert(office_patterns, xls_wide_pattern, sizeof(xls_wide_pattern),
                "xls");

      const unsigned char ppt_pattern[] = {0x50, 0x50, 0x54};

      const unsigned char ppt_wide_pattern[] = {0x50, 0x00, 0x50, 0x00, 0x54};
      ac_insert(office_patterns, ppt_pattern, sizeof(ppt_pattern), "ppt");
      ac_insert(office_patterns, ppt_wide_pattern, sizeof(ppt_wide_pattern),
                "ppt");
      const unsigned char wps_pattern[] = {
          0x57, 0x00, 0x50, 0x00, 0x53, 0x00, 0x20, 0x00, 0x4F, 0x00,
          0x66, 0x00, 0x66, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65};
      ac_insert(office_patterns, wps_pattern, sizeof(wps_pattern), "wps");
    // Office 2007+模式
    ac_insert(office_patterns, (const unsigned char *)"xl/", 3, "xlsx");
    ac_insert(office_patterns, (const unsigned char *)"word/", 5, "docx");
    ac_insert(office_patterns, (const unsigned char *)"ppt/", 4, "pptx");

    // WPS模式
    ac_insert(office_patterns, (const unsigned char *)"docProps/PK", 11, "wps");

    // XML/HTML相关
    ac_insert(office_patterns, (const unsigned char *)"<?xml version=\"1.0\"",
              19, "xml");
    ac_insert(office_patterns, (const unsigned char *)"<!DOCTYPE html>", 15,
              "html");
    ac_insert(office_patterns, (const unsigned char *)"JavaScript", 10, "js");

    build_failure_links(office_patterns);
}
int dpi_detect_office_type(char *payload, uint16_t payload_len, char *buff) {

  pthread_once(&office_once, init_office_patterns);
  if (ac_search(office_patterns, payload, payload_len, buff)) {
    return 1;
  }

  return 0;
}

int detect_file_type(char *payload, uint16_t payload_len, char *buff) {
  int ret = 0;
  if (buff == NULL || payload == NULL || payload_len < 5) {
    return 0;
  }

  if (payload[0] == '7' && payload[1] == 'z') {
    strncpy(buff, "7z", COMMON_SOME_TYPE - 1);
    return 1;
  }
  if (*payload == '{' && *(payload + payload_len - 1) == '}') {
    strncpy(buff, "json", 4);
    return 1;
  }
  int check_len = 56;
  if (check_len > (int)payload_len) {
    check_len = payload_len;
  }

  uint32_t header = 0;   // 前4字节
  uint32_t header_4 = 0; // 4-8字节
  header = get_uint32_ntohl(payload, 0);
  uint32_t header_3bytes = (header & 0xffffff00) >> 8;
  uint32_t header_2bytes = (header & 0xffff0000) >> 16;
  header_4 = get_uint32_ntohl(payload, 4);

  if (header_2bytes == 0xffd8) {
    strncpy(buff, "JPG", COMMON_SOME_TYPE - 1);
    return 1;
  }
  // 使用AC自动机统一检测所有模式
  if (dpi_detect_office_type(payload, payload_len, buff)) {
    return 1;
  }

  for (unsigned i = 0; i < sizeof(dpi_file_table) / sizeof(dpi_file_table[0]);
       i++) {
    if (header_3bytes == dpi_file_table[i].code) {
      if (dpi_file_table[i].file_type[0] == 'z' &&
          dpi_file_table[i].file_type[1] == 'i' &&
          dpi_file_table[i].file_type[2] == 'p') {
        if (KMP(payload, payload_len > 512 ? 512 : payload_len, "Android", 2) !=
            -1) {
          strncpy(buff, "apk", COMMON_SOME_TYPE - 1);
          return 1;
        }
      }

      strncpy(buff, dpi_file_table[i].file_type, COMMON_SOME_TYPE - 1);
      return 1;
    }
  }
  return 0;
}

int read_file(const char *file_name) {
  printf("file name is %s\n", file_name);

  FILE *fp = fopen(file_name, "rb");
  if (fp == NULL) {
    printf("open file failed\n");
    return -1;
  }

  // Move file pointer to the end of the file
  fseek(fp, 0, SEEK_END);
  int file_size = ftell(fp);
  printf("file size is %d\n", file_size);

  // Move file pointer back to the beginning of the file
  fseek(fp, 0, SEEK_SET);

  char suffix[64];
  char *payload = malloc(file_size);
  if (payload == NULL) {
    printf("memory allocation failed\n");
    fclose(fp);
    return -1;
  }

  memset(payload, 0, file_size);
  fread(payload, 1, file_size, fp);
  // printf("\n%s\n", payload);

  detect_file_type(payload, file_size, suffix);
  printf("file type is %s\n", suffix);

  free(payload);
  fclose(fp);
  return 0;
}

int main(int argc, char *argv[]) {
  char *file_name = argv[1];
  read_file(file_name);
  return 0;
}
