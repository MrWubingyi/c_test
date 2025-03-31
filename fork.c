#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();  // 创建子进程

    if (pid == -1) {
        // 如果 fork() 失败，则打印错误并退出
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // 这是子进程执行的代码区域
        // 使用 execl() 替换子进程的镜像，执行 ls 命令
        execl("/bin/bash", "watch -n 1 'date' ", NULL);

        // 如果 execl() 执行失败，我们需要终止子进程
        perror("execl() failure");
        _exit(EXIT_FAILURE);  // 使用 _exit 而不是 exit，以避免触发清理动作
    } else {
        // 这是父进程执行的代码区域
        // 父进程可以继续做其它工作，而不必等待子进程结束

        // 例如，可以打印一些信息或处理其他任务
        printf("This is the parent process. The child process ID is %d\n", pid);
        printf("Parent process continues to run...\n");

        // 如果需要，这里可以调用 waitpid() 非阻塞地等待子进程结束
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);  // WNOHANG 是非阻塞的关键
        if (result == 0) {
            // 子进程仍在运行
            printf("Child process is still running\n");
        } else if (result == -1) {
            // waitpid() 出错
            perror("waitpid");
        } else {
            // 子进程已结束
            printf("Child process exited with status %d\n", status);
        }

        // 父进程的其他逻辑
        // ...
    }

    return EXIT_SUCCESS;
}
