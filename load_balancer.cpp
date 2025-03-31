#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <chrono>
#include <thread>

// 假设数据包结构
struct Packet {
    std::string ip; // 包含一个IP字段，实际中可以有更多信息
    int seq;        // 新增序列号字段
};

// 线程结构
struct Thread {
    bool isBlocked;   // 阻塞状态
    bool isQueueFull; // 队列是否满
    std::vector<Packet> queue; // 模拟队列
    std::string subnet; // 当前处理的网段（如果有）
    int id; // 线程ID
};

// 全局线程池
const int m = 5;  // 假设有5个处理线程
Thread threadPool[m]; // 处理线程池
std::vector<Thread*> DealingthreadPool; // 活跃的处理线程池
std::unordered_map<int, Thread*> subnetToThreadMap;  // 记录网段哈希值到线程的映射关系
int currentIndex = 0; // 当前调度线程的位置

// 简单的哈希函数，将网段映射到处理线程
int mapSubnetToThread(const std::string& subnet) {
    std::hash<std::string> hasher;
    return hasher(subnet) % DealingthreadPool.size();  // 根据活跃线程池大小映射
}

// 从IP地址中提取前三部分作为网段
std::string getSubnet(const std::string& ip) {
    std::stringstream ss(ip);
    std::string part;
    std::string subnet;

    int count = 0;
    while (std::getline(ss, part, '.') && count < 3) {
        subnet += part;
        if (count < 2) {
            subnet += ".";  // 加入点符号
        }
        count++;
    }
    return subnet;  // 返回前三部分作为网段
}

// 插入数据包到目标线程队列
bool insertIntoQueue(Thread* thread, Packet packet) {
    // 队列满则标记线程为阻塞
    if (thread->queue.size() >= 20) {  // 假设队列容量为3
        thread->isQueueFull = true;
        return false;
    }

    // 向队列插入数据包
    thread->queue.push_back(packet);

    // 队列未满，标记为可用
    thread->isQueueFull = false;
    return true;
}

// 查找下一个可用的线程（根据网段）
Thread* findNextAvailableThread(const std::string& subnet) {
    // 优先选择已经绑定到该网段的线程
    int subnetHash = mapSubnetToThread(subnet); // 计算网段的哈希值
    std::cout << "Hash for subnet " << subnet << " is " << subnetHash << std::endl;
    if (subnetToThreadMap.find(subnetHash) != subnetToThreadMap.end()) {
      std::cout << "Found existing thread for subnet " << subnet << std::endl;
        Thread* assignedThread = subnetToThreadMap[subnetHash];
        if (!assignedThread->isBlocked && !assignedThread->isQueueFull) {
            return assignedThread;  // 如果已经有线程绑定并且未阻塞，直接分配
        }
    }
      int ring_id = subnetHash % DealingthreadPool.size();
      if(!DealingthreadPool[ring_id]->isBlocked){
            Thread* thread = DealingthreadPool[ring_id];
            subnetToThreadMap[subnetHash] = thread;
            return DealingthreadPool[ring_id];
      }

    // 如果没有找到绑定的线程，或者当前线程被阻塞，则根据DealingthreadPool动态选择
    for (int i = 0; i < DealingthreadPool.size(); i++) {
      std::cout << "Checking thread " << (currentIndex + i) % DealingthreadPool.size() << std::endl;
        Thread* thread = DealingthreadPool[(currentIndex + i) % DealingthreadPool.size()];
        if (!thread->isBlocked && !thread->isQueueFull) {
            // 将该网段绑定到找到的线程
            subnetToThreadMap[subnetHash] = thread;
            return thread;
        }
    }

    return nullptr;  // 如果没有找到可用的线程
}

// 标记线程为阻塞，并从DealingthreadPool移除
void markThreadAsBlocked(Thread* thread) {
    thread->isBlocked = true;
    // 从活跃线程池中移除
    DealingthreadPool.erase(std::remove(DealingthreadPool.begin(), DealingthreadPool.end(), thread), DealingthreadPool.end());
}

// 标记线程为空闲，并加入DealingthreadPool
void markThreadAsAvailable(Thread* thread) {
    thread->isBlocked = false;
    DealingthreadPool.push_back(thread);
}

// 打印线程池队列状态
void printThreadPoolStatus() {
    for (int i = 0; i < m; i++) {
        std::cout << "Thread " << i << " [Blocked: " << threadPool[i].isBlocked 
                  << ", Queue Full: " << threadPool[i].isQueueFull
                  << ", Queue Size: " << threadPool[i].queue.size() << "] ";
        if (!threadPool[i].queue.empty()) {
            std::cout << "Queue Contents: ";
            std::unordered_map<std::string, int> ip_seq_map;
            // 找出每个IP的最新seq
            for (const auto& pkt : threadPool[i].queue) {
                if (ip_seq_map.find(pkt.ip) == ip_seq_map.end() || pkt.seq > ip_seq_map[pkt.ip]) {
                    ip_seq_map[pkt.ip] = pkt.seq;
                }
            }
            // 输出合并后的结果
            for (const auto& entry : ip_seq_map) {
                std::cout << entry.first << "(" << entry.second << ") |"; 
            }
        }
        std::cout << std::endl;
    }
}

// 数据包调度
void dispatchPacket(Packet packet) {
    std::string subnet = getSubnet(packet.ip);  // 提取前三部分作为网段
    std::cout << "Dispatching packet with IP " << packet.ip << " to subnet " << subnet << std::endl;
    Thread* availableThread = findNextAvailableThread(subnet);
    if (availableThread == nullptr) {
        std::cout << "No available threads for subnet " << subnet << std::endl;
        return;
    }

    std::cout << "Dispatching packet with IP " << packet.ip << " to Thread " << availableThread->id << std::endl;
    insertIntoQueue(availableThread, packet);
}

int main() {
    // 初始化线程池和DealingthreadPool
    for (int i = 0; i < m; i++) {
        threadPool[i].isBlocked = false;
        threadPool[i].isQueueFull = false;
        threadPool[i].subnet = "";  // 初始化网段为空
        DealingthreadPool.push_back(&threadPool[i]);  // 将所有线程加入活跃线程池
        threadPool[i].id = i;
    }

    // 持续调度循环
    int seq_counter = 0;
    int subnet_counter = 0;
    int current_thread_id = 0;
    auto last_switch_time = std::chrono::steady_clock::now();

    while(true) {
        // 生成带重复IP和seq的新数据包
        Packet new_packet;
        subnet_counter += rand() ;
        subnet_counter = subnet_counter % 4;
        new_packet.ip = "192.168." + std::to_string(1 + (subnet_counter % 4)) + "." + std::to_string(1 + (seq_counter % 4)); // IP重复模式
        new_packet.seq = seq_counter++;
        dispatchPacket(new_packet);

        // 检查5秒时间间隔
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_switch_time).count() >= 5) {
            // 切换当前线程的阻塞状态
            Thread* target = &threadPool[current_thread_id];
            Thread* target_next = &threadPool[current_thread_id+1];
            if (target->isBlocked) {
                markThreadAsAvailable(target);
                std::cout << "\nUnblocked thread " << current_thread_id << std::endl;
            } else {
                markThreadAsBlocked(target);
                std::cout << "\nBlocked thread " << current_thread_id << std::endl;
            }
            if (target_next->isBlocked) {
                markThreadAsAvailable(target_next);
                std::cout << "\nUnblocked thread " << current_thread_id+1<< std::endl;
            } else {
                markThreadAsBlocked(target_next);
                std::cout << "\nBlocked thread " << current_thread_id+1 << std::endl;
            }
            // 更新索引和计时器
            current_thread_id = (current_thread_id + 1) % m;
            last_switch_time = now;
        }

        // 添加适当延时避免CPU满载
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // 每隔2秒打印一次队列状态（500ms*4=2秒）
        static int counter = 0;
        if (++counter % 4 == 0) {
            std::cout << "\n===== 当前队列状态 =====" << std::endl;
            printThreadPoolStatus();
            std::cout << "=======================\n" << std::endl;
        }
    }

    // 打印线程池的队列状态
    std::cout << "\nThread Pool Status after dispatching packets:\n";
    printThreadPoolStatus();

    // 模拟阻塞一些线程（假设Thread 1阻塞）
    markThreadAsBlocked(&threadPool[1]);
    std::cout << "\nThread 1 is marked as blocked.\n";


    // 打印线程池的队列状态
    std::cout << "\nThread Pool Status after more dispatches:\n";
    printThreadPoolStatus();

    return 0;
}
