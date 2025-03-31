#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_THREADS 10
#define MAX_PACKETS 100

typedef struct {
    char ip[16];
} Packet;

typedef struct {
    int isBlocked;
    Packet queue[MAX_PACKETS];
    int queueSize;
} Thread;

Thread threadPool[MAX_THREADS];

void dispatchPacket(Packet packet) {
    // 简单的调度逻辑：找到第一个未阻塞的线程并将数据包加入其队列
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!threadPool[i].isBlocked && threadPool[i].queueSize < MAX_PACKETS) {
            threadPool[i].queue[threadPool[i].queueSize++] = packet;
            printf("Dispatched packet to thread %d\n", i);
            return;
        }
    }
    printf("No available thread to dispatch packet\n");
}

void printThreadPoolStatus() {
    for (int i = 0; i < MAX_THREADS; i++) {
        printf("Thread %d: %s, Queue Size: %d\n", i, threadPool[i].isBlocked ? "Blocked" : "Active", threadPool[i].queueSize);
    }
}

void markThreadAsBlocked(Thread* thread) {
    thread->isBlocked = 1;
}

int main() {
    // 初始化线程池
    for (int i = 0; i < MAX_THREADS; i++) {
        threadPool[i].isBlocked = 0;
        threadPool[i].queueSize = 0;
    }

    // 调度数据包
    Packet packets[] = {{"192.168.1.1"}, {"192.168.1.2"}, {"192.168.1.3"}, {"192.168.1.4"}};
    int numPackets = sizeof(packets) / sizeof(packets[0]);

    for (int i = 0; i < numPackets; i++) {
        dispatchPacket(packets[i]);
    }

    // 打印线程池的队列状态
    printf("\nThread Pool Status after dispatching packets:\n");
    printThreadPoolStatus();

    // 模拟阻塞一些线程（假设Thread 1阻塞）
    markThreadAsBlocked(&threadPool[1]);
    printf("\nThread 1 is marked as blocked.\n");

    // 继续调度新的数据包
    Packet newPackets[] = {{"192.168.1.5"}, {"192.168.3.3"}};
    int numNewPackets = sizeof(newPackets) / sizeof(newPackets[0]);

    for (int i = 0; i < numNewPackets; i++) {
        dispatchPacket(newPackets[i]);
    }

    // 打印线程池的队列状态
    printf("\nThread Pool Status after more dispatches:\n");
    printThreadPoolStatus();

    return 0;
}