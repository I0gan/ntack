#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>

#define PORT 40404
#define MAXMSG 512

static void die(char* s) {
    perror(s);
    exit(EXIT_FAILURE);
}
int auth(int fd) {
#define LOGIN_STR "passwd:"
#define LOGIN_FAILED_STR "Auth failed!\n"
#define LOGIN_SUCCESS_STR "Auth Success!\n"
#define PASSWD_STR "i0gan"
    write(fd, LOGIN_STR, sizeof(LOGIN_STR));
    char buf[64];
    read(fd, buf, 64);
    int ret = (strncmp(buf, PASSWD_STR, sizeof(PASSWD_STR) - 1) == 0);
    if(ret == 0)
        write(fd, LOGIN_FAILED_STR, sizeof(LOGIN_FAILED_STR) - 1);
    else
        write(fd, LOGIN_SUCCESS_STR, sizeof(LOGIN_SUCCESS_STR) - 1);
    return ret;
}

int bind_listen(int port) {
    int sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        die ("socket");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons (port),
    };
    addr.sin_addr.s_addr = htonl (INADDR_ANY);
    int on=1;  
    if((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) == -1)
        die("setsockopt");
    
    if (bind (sockfd, (struct sockaddr *) &addr, sizeof addr) == -1)
        die ("bind");
    
    if (listen (sockfd, 5) == -1)
        die ("listen");
    printf("Listening on %s port %d\n", inet_ntoa(addr.sin_addr), port);
    return sockfd;
}

void run() {
    int sockfd = bind_listen(PORT);
    while(1) {
        int fd = accept(sockfd, NULL, NULL);
        if (fd == -1) die("accept");
        if(!auth(fd)) {
            close(fd);
            continue;
        }
        printf("Accept connection\n");
        int masterFd = posix_openpt(O_RDWR | O_NOCTTY);
        if (masterFd == -1) die("posix_openpt");
        if (grantpt(masterFd) == -1) die("grantpt");
        if (unlockpt(masterFd) == -1) die("unlockpt");
        char* slname = ptsname(masterFd);
        if (slname == NULL) die("ptsname");

        pid_t cpid = fork();
        if (cpid == -1) die("fork");

        if (cpid == 0) {        /* Child */
            if (setsid() == -1) die("setsid");
            close(masterFd);
            int slavedFd = open(slname, O_RDWR);
            if (slavedFd == -1) die("open slave pseudo-terminal");

            if (ioctl(slavedFd, TIOCSCTTY) == -1)
                die("ioctl TIOCSCTTY 设置控制终端");

            struct winsize ws = {
                .ws_col = 80,   /* XXX 应该设置成客户端用户所使用的终端的大小 */
                .ws_row = 25,
            };
            if (ioctl(slavedFd, TIOCSWINSZ, &ws) == -1)
                die("ioctl TIOCSWINSZ 窗口大小");

            if (dup2(slavedFd, STDIN_FILENO) == -1) die("dup2");
            if (dup2(slavedFd, STDOUT_FILENO) == -1) die("dup2");
            if (dup2(slavedFd, STDERR_FILENO) == -1) die("dup2");

            execlp("sh", "sh", "-i", NULL);
            perror("execlp");
            _exit(EXIT_FAILURE);
        }

        /* Parent */
        while(1) {
            fd_set read_fd_set;
            FD_ZERO(&read_fd_set);
            FD_SET(fd, &read_fd_set);
            FD_SET(masterFd, &read_fd_set);

            if (select(masterFd+1, &read_fd_set, NULL, NULL, NULL) == -1)
                die("select");

            if (FD_ISSET(fd, &read_fd_set)) {
                char buffer[MAXMSG];
                ssize_t nread = read(fd, buffer, MAXMSG);
                if (nread == -1) {
                    perror("read");
                    close(fd);
                    close(masterFd);
					break;
				}
                else if (nread == 0) {
                    fprintf(stderr, "got end-of-file from client, closing\n");
                    close(fd);
                    break;
                } else {
                    write(masterFd, buffer, nread);
                }
            }
            if (FD_ISSET(masterFd, &read_fd_set)) {
                char buffer[MAXMSG];
                ssize_t nread = read(masterFd, buffer, MAXMSG);
                if (nread == -1) {
                    perror("read");
                    close(fd);
                    close(masterFd);
                    break;
                }
                else if (nread == 0) {
                    fprintf(stderr, "got end-of-file from terminal, quit\n");
                    break;
                    //exit(EXIT_FAILURE);
                } else {
                    if (write(fd, buffer, nread) != nread)
                        perror("partial/failed write");
                }
            }
        }
        kill(cpid, SIGTERM);
    }
}

int main(void) {
    run();
    return 0; 
} 
