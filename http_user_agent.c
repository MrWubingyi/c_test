// 辅助函数：检查是否匹配关键字（不区分大小写）
static int check_keyword(const char *str, size_t len, const char *keyword) {
    size_t keyword_len = strlen(keyword);
    if (len < keyword_len) return 0;
    return strncasecmp(str, keyword, keyword_len) == 0;
}

// 辅助函数：查找token结束位置
static const char *find_token_end(const char *start, size_t remaining_len) {
    for (size_t i = 0; i < remaining_len; i++) {
        if (start[i] == ';' || start[i] == ')' || start[i] == '\r' || start[i] == '\n') {
            return start + i;
        }
    }
    return start + remaining_len;
}

static void dissect_http_user_agent(struct http_request_info *line_info) {
    struct header_value *value = (struct header_value *)g_hash_table_lookup(line_info->table, "user-agent");
    if (!value) {
        return;
    }

    line_info->user_agent_num++;
    
    const char *ptr = (const char *)value->ptr;
    size_t len = value->len;
    const char *devFlags[] = {"linux", "windows ", "windows/", "iphone ", "android", "mac", NULL};

    // 初始化缓冲区
    line_info->uaCPU[0] = '\0';
    line_info->uaOS[0] = '\0';

    for (size_t i = 0; i < len; ) {
        // 检查CPU信息
        if (!line_info->uaCPU[0] && i + 2 < len && check_keyword(ptr + i, len - i, "cpu")) {
            const char *token_start = ptr + i;
            const char *token_end = find_token_end(token_start, len - i);
            size_t copy_len = MIN(token_end - token_start, CPU_LEN - 1);
            memcpy(line_info->uaCPU, token_start, copy_len);
            line_info->uaCPU[copy_len] = '\0';
            i += (token_end - token_start);
            continue;
        }

        // 检查OS信息
        if (!line_info->uaOS[0]) {
            for (int j = 0; devFlags[j]; j++) {
                size_t flag_len = strlen(devFlags[j]);
                if (i + flag_len < len && check_keyword(ptr + i, len - i, devFlags[j])) {
                    const char *token_start = ptr + i;
                    const char *token_end = find_token_end(token_start, len - i);
                    size_t copy_len = MIN(token_end - token_start, OS_LEN - 1);
                    memcpy(line_info->uaOS, token_start, copy_len);
                    line_info->uaOS[copy_len] = '\0';
                    i += (token_end - token_start);
                    break;
                }
            }
        }

        // 如果已经找到所有信息，提前退出
        if (line_info->uaCPU[0] && line_info->uaOS[0]) {
            break;
        }

        i++;
    }
}
