#include <cstddef>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <dirent.h>

#define RTP_HEADER_SIZE 12
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20
#define GTP_HEADER_SIZE 8
#define GTP_PORT 2152
#define MAX_PORTS 50

typedef struct {
    uint32_t ssrc;
    uint16_t last_seq;
    uint8_t payload_type;
    bool first_packet;
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int discontinuity_count;
    int identical_seq_count;
    int packet_num;
} rtp_stream_t;

typedef struct {
    uint16_t audio_port;
    uint16_t video_port;
    char audio_encoding[10];
    char video_encoding[10];
} sip_stream_t;

rtp_stream_t *streams = NULL;
sip_stream_t *sip_streams = NULL;
int max_streams = 0;
int sip_stream_count = 0;
int stream_count = 0;

uint16_t sip_audio_ports[MAX_PORTS];
uint16_t sip_video_ports[MAX_PORTS];
int audio_port_count = 0;
int video_port_count = 0;

typedef struct {
    uint8_t payload_type;
    const char *description;
} rtp_payload_type_t;

rtp_payload_type_t payload_type_desc[] = {
    { 0, "ITU-T G.711 PCMU" },
    { 1, "USA Federal Standard FS-1016" },
    { 2, "ITU-T G.721" },
    { 3, "GSM 06.10" },
    { 4, "ITU-T G.723" },
    { 5, "DVI4 8000 samples/s" },
    { 6, "DVI4 16000 samples/s" },
    { 7, "Experimental linear predictive encoding from Xerox PARC" },
    { 8, "ITU-T G.711 PCMA" },
    { 9, "ITU-T G.722" },
    { 10, "16-bit uncompressed audio, stereo" },
    { 11, "16-bit uncompressed audio, monaural" },
    { 12, "Qualcomm Code Excited Linear Predictive coding" },
    { 13, "Comfort noise" },
    { 14, "MPEG-I/II Audio" },
    { 15, "ITU-T G.728" },
    { 16, "DVI4 11025 samples/s" },
    { 17, "DVI4 22050 samples/s" },
    { 18, "ITU-T G.729" },
    { 19, "Comfort noise (old)" },
    { 25, "Sun CellB video encoding" },
    { 26, "JPEG-compressed video" },
    { 31, "ITU-T H.261" },
    { 32, "MPEG-I/II Video" },
    { 33, "MPEG-II transport streams" },
    { 34, "ITU-T H.263" },
    { 8, "G711" },
    { 0, NULL }
};

const char* get_payload_type_description(rtp_stream_t stream) {
    for (int i = 0; payload_type_desc[i].description != NULL; ++i) {
        if (payload_type_desc[i].payload_type == stream.payload_type) {
            return payload_type_desc[i].description;
        }
    }
    for (int i = 0; i < sip_stream_count; i++) {
        if (stream.src_port == sip_streams[i].audio_port || stream.dst_port == sip_streams[i].audio_port) {
            return sip_streams[i].audio_encoding;
        }
        if (stream.src_port == sip_streams[i].video_port || stream.dst_port == sip_streams[i].video_port) {
            return sip_streams[i].video_encoding;
        }
    }
    return "Unknown Payload Type";
}

struct ip *iph = NULL;
struct tcphdr *tcph = NULL;
struct udphdr *udph = NULL;

const u_char *process_encapsulation(const u_char *packet, int *len) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    uint16_t eth_type = ntohs(eth->h_proto);
    if (ntohs(packet[0]) == 0x0200) {
        packet += 4;
        *len -= 4;
        eth_type = ntohs(*(uint16_t *)packet);
        iph = (struct ip *)packet;
        int ip_header_len = iph->ip_hl * 4;
        packet += ip_header_len;
        *len -= ip_header_len;

        if (iph->ip_p == IPPROTO_UDP) {
            udph = (struct udphdr *)packet; 
            packet += UDP_HEADER_SIZE;
            *len -= UDP_HEADER_SIZE;
        } else if (iph->ip_p == IPPROTO_TCP) {
            tcph = (struct tcphdr *)packet;
            int tcp_header_len = tcph->doff * 4;
            packet += tcp_header_len;
            *len -= tcp_header_len;
        }
        return packet;
}
    packet += 14;
    *len -= 14;
    iph = NULL;
    tcph = NULL;
    udph = NULL;
    if (eth_type == 0x8100) {
        packet += 4;
        *len -= 4;
        eth_type = ntohs(*(uint16_t *)packet);
        packet += 2;
        *len -= 2;
    }


    if (eth_type == 0x8847) {
        while ((packet[2] & 0x01) == 0) {
            packet += 4;
            *len -= 4;
        }
        packet += 4;
        *len -= 4;
    }

    if (eth_type == 0x0800) {
        iph = (struct ip *)packet;
        int ip_header_len = iph->ip_hl * 4;
        packet += ip_header_len;
        *len -= ip_header_len;

        if (iph->ip_p == IPPROTO_UDP) {
            udph = (struct udphdr *)packet; 
            packet += UDP_HEADER_SIZE;
            *len -= UDP_HEADER_SIZE;
        } else if (iph->ip_p == IPPROTO_TCP) {
            tcph = (struct tcphdr *)packet;
            int tcp_header_len = tcph->doff * 4;
            packet += tcp_header_len;
            *len -= tcp_header_len;
        }
    } else if (eth_type == 0x86DD) {
        packet += sizeof(struct ip6_hdr);
        *len -= sizeof(struct ip6_hdr);
    }

    return packet;
}

bool is_rtp_packet(const u_char *packet, int len) {
    if (len < RTP_HEADER_SIZE) return false;
    uint8_t version = (packet[0] >> 6) & 0x03;
    uint8_t payload_type = packet[1] & 0x7F;
    return (version == 2) && (payload_type <= 127);
}

void process_rtp_packet(const u_char *payload, int len) {
    if (!is_rtp_packet(payload, len)) return;

    uint32_t ssrc = ntohl(*(uint32_t *)(payload + 8));
    uint16_t seq_number = ntohs(*(uint16_t *)(payload + 2));
    uint8_t payload_type = payload[1] & 0x7F;

    for (int i = 0; i < stream_count; ++i) {
        if (streams[i].ssrc == ssrc) {
            if (!streams[i].first_packet && streams[i].last_seq == seq_number) {
                streams[i].identical_seq_count++;
            }
            if (!streams[i].first_packet && streams[i].last_seq + 1 != seq_number) {
                streams[i].discontinuity_count++;
            }
            streams[i].last_seq = seq_number;
            streams[i].first_packet = false;
            streams[i].payload_type = payload_type;
            streams[i].packet_num++;
            return;
        }
    }

    if (stream_count >= max_streams) {
        max_streams = max_streams ? max_streams * 2 : 100;
        streams = (rtp_stream_t *)realloc(streams, max_streams * sizeof(rtp_stream_t));
        sip_streams = (sip_stream_t *)realloc(sip_streams, max_streams * sizeof(sip_stream_t));
    }

    streams[stream_count].ssrc = ssrc;
    streams[stream_count].last_seq = seq_number;
    streams[stream_count].first_packet = true;
    streams[stream_count].payload_type = payload_type;
    streams[stream_count].discontinuity_count = 0;
    streams[stream_count].identical_seq_count = 0;
    if (iph) {
        streams[stream_count].src_ip = iph->ip_src;
        streams[stream_count].dst_ip = iph->ip_dst;
    }
    if (udph) {
        streams[stream_count].src_port = ntohs(udph->source);
        streams[stream_count].dst_port = ntohs(udph->dest);
    } else if (tcph) {
        streams[stream_count].src_port = ntohs(tcph->source);
        streams[stream_count].dst_port = ntohs(tcph->dest);
    }
    stream_count++;
}

void extract_sip_ports(const u_char *payload, int len) {
    const char *sip_video_pattern = "m=video ";
    const char *rtpmap_pattern = "a=rtpmap:";
    char *data = (char *)payload;

    char *video_match = strstr(data, sip_video_pattern);

    if (video_match) {
        if (sip_stream_count >= max_streams) {
            max_streams = max_streams ? max_streams * 2 : 100;
            streams = (rtp_stream_t *)realloc(streams, max_streams * sizeof(rtp_stream_t));
            sip_streams = (sip_stream_t *)realloc(sip_streams, max_streams * sizeof(sip_stream_t));
        }

        sip_stream_t *stream = &sip_streams[sip_stream_count];
        uint16_t port;
        int payload_type;
        if (sscanf(video_match + strlen(sip_video_pattern), "%hu RTP/AVP %d", &port, &payload_type) == 2) {
            stream->video_port = port;

            char rtpmap_search[20];
            snprintf(rtpmap_search, sizeof(rtpmap_search), "%s%d ", rtpmap_pattern, payload_type);
            char *rtpmap_match = strstr(data, rtpmap_search);
            if (rtpmap_match) {
                char encoding[10];
                if (sscanf(rtpmap_match + strlen(rtpmap_search), "%9s", encoding) == 1) {
                    strncpy(stream->video_encoding, encoding, sizeof(stream->video_encoding) - 1);
                    stream->video_encoding[sizeof(stream->video_encoding) - 1] = '\0';
                }
            }
        }
        sip_stream_count++;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int len = header->caplen;
    const u_char *payload = process_encapsulation(packet, &len);
    extract_sip_ports(payload, len);
    process_rtp_packet(payload, len);
}

int main(int argc, char *argv[]) {
    bool quiet_mode = false;
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s [-q] -i <pcap file> OR -d <pcap directory>\n", argv[0]);
        return 1;
    }
    
    int arg_offset = 1;
    if (strcmp(argv[1], "-q") == 0) {
        quiet_mode = true;
        arg_offset = 2;
        if (argc != 4) {
            fprintf(stderr, "Usage: %s [-q] -i <pcap file> OR -d <pcap directory>\n", argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    
    if (strcmp(argv[arg_offset], "-i") == 0) {
        handle = pcap_open_offline(argv[arg_offset+1], errbuf);
        pcap_loop(handle, 0, packet_handler, NULL);
        pcap_close(handle);
    } else if (strcmp(argv[arg_offset], "-d") == 0) {
        DIR *dir;
        struct dirent *ent;
        if ((dir = opendir(argv[arg_offset+1])) != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                if (strstr(ent->d_name, ".pcap")) {
                    char filepath[1024];
                    snprintf(filepath, sizeof(filepath), "%s/%s", argv[arg_offset+1], ent->d_name);
                    handle = pcap_open_offline(filepath, errbuf);
                    if (handle) {
                        pcap_loop(handle, 0, packet_handler, NULL);
                        pcap_close(handle);
                    }
                }
            }
            closedir(dir);

        } else {
            fprintf(stderr, "Could not open directory %s\n", argv[2]);
            return 1;
        }
    } else {
        fprintf(stderr, "Invalid option: %s\n", argv[1]);
        return 1;
    }

    if (!handle) {
        fprintf(stderr, "Could not open file %s: %s\n", argv[2], errbuf);
        return 1;
    }


    if (stream_count > 0) {
        int total_packets = 0;
        int abnormal_packets = 0;
        int unknown_payload_count = 0;
        int low_packet_count = 0;
        int disordered_count = 0;
        int duplicate_count = 0;
        
        for (int i = 0; i < stream_count; ++i) {
            total_packets += streams[i].packet_num;
            abnormal_packets += streams[i].discontinuity_count + streams[i].identical_seq_count;
            
            const char *payload_type_name = get_payload_type_description(streams[i]);
            if (strcmp(payload_type_name, "Unknown Payload Type") == 0) {
                unknown_payload_count++;
            }
            if (streams[i].packet_num < 10) {
                low_packet_count++;
            }
            if (streams[i].discontinuity_count > 0) {
                disordered_count++;
            }
            if (streams[i].identical_seq_count > 0) {
                duplicate_count++;
            }
        }
        
        if (!quiet_mode) {
            printf("RTP流的数量: %d\n", stream_count);
            printf("异常RTP流量占比: %.2f%%\n", (abnormal_packets * 100.0) / total_packets);
            
            for (int i = 0; i < stream_count; ++i) {
                char src_ip[INET_ADDRSTRLEN] = {0};
                char dst_ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &(streams[i].src_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(streams[i].dst_ip), dst_ip, INET_ADDRSTRLEN);
                const char *payload_type_name = get_payload_type_description(streams[i]);
                printf("RTP流 %s:%d->%s:%d  SSRC: 0x%X, Payload Type: %s, 包数 %d ,序号不连续次数: %d, 序号完全相同次数: %d\n",
                      src_ip, streams[i].src_port, dst_ip, streams[i].dst_port, 
                      streams[i].ssrc, payload_type_name, streams[i].packet_num,
                      streams[i].discontinuity_count, streams[i].identical_seq_count);
            }
        } else {
            printf("异常流统计:\n");
            printf("未知Payload类型流: %.2f%% (%d/%d)\n", 
                  (unknown_payload_count * 100.0) / stream_count, unknown_payload_count, stream_count);
            printf("包数小于10的流: %.2f%% (%d/%d)\n", 
                  (low_packet_count * 100.0) / stream_count, low_packet_count, stream_count);
            printf("发生乱序的流: %.2f%% (%d/%d)\n", 
                  (disordered_count * 100.0) / stream_count, disordered_count, stream_count);
            printf("发生重复包的流: %.2f%% (%d/%d)\n", 
                  (duplicate_count * 100.0) / stream_count, duplicate_count, stream_count);
            
            int total_abnormal_streams = 0;
            for (int i = 0; i < stream_count; ++i) {
                const char *payload_type_name = get_payload_type_description(streams[i]);
                if ((strcmp(payload_type_name, "Unknown Payload Type") == 0) ||
                    (streams[i].packet_num < 10) ||
                    (streams[i].discontinuity_count > 0) ||
                    (streams[i].identical_seq_count > 0)) {
                    total_abnormal_streams++;
                }
            }
            printf("总异常流占比: %.2f%% (%d/%d)\n", 
                  (total_abnormal_streams * 100.0) / stream_count, total_abnormal_streams, stream_count);
            printf("总异常RTP包占比: %.2f%%\n", (abnormal_packets * 100.0) / total_packets);
            
            printf("\n异常流详细信息:\n");
            for (int i = 0; i < stream_count; ++i) {
                const char *payload_type_name = get_payload_type_description(streams[i]);
                bool is_abnormal = (strcmp(payload_type_name, "Unknown Payload Type") == 0) ||
                                   (streams[i].packet_num < 10) ||
                                   (streams[i].discontinuity_count > 0) ||
                                   (streams[i].identical_seq_count > 0);
                
                if (is_abnormal) {
                    char src_ip[INET_ADDRSTRLEN] = {0};
                    char dst_ip[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &(streams[i].src_ip), src_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(streams[i].dst_ip), dst_ip, INET_ADDRSTRLEN);
                    printf("RTP流 %s:%d->%s:%d  SSRC: 0x%X, Payload Type: %s, 包数 %d ,序号不连续次数: %d, 序号完全相同次数: %d\n",
                          src_ip, streams[i].src_port, dst_ip, streams[i].dst_port, 
                          streams[i].ssrc, payload_type_name, streams[i].packet_num,
                          streams[i].discontinuity_count, streams[i].identical_seq_count);
                }
            }
        }
    }

    free(streams);
    free(sip_streams);
    return 0;
}
