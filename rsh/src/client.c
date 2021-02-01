#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

static void die(char* s) {
    perror(s);
    exit(EXIT_FAILURE);
}

struct termios user_termios;

static void enable_raw_mode(int fd) {
    struct termios t;
    if (tcgetattr(fd, &t) == -1) die("tcgetattr");
    user_termios = t;
    t.c_lflag &= ~(ICANON | ECHO | ISIG | IEXTEN);
    t.c_iflag &= ~(ICRNL | INLCR | IXON);
    t.c_oflag &= ~OPOST;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSAFLUSH, &t) == -1)
        die("tcsetattr");
}

static void disable_raw_mode(void) {
    if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &user_termios) == -1)
        die("tcsetattr");
}


int main(int argc, char* argv[]) {
    if (argc < 4 || strcmp(argv[1], "--help") == 0) {
        fprintf(stderr, "usage: %s host port passwd\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* host = argv[1];
    errno = 0;
    int port = strtol(argv[2], 0, 10);
    if (errno != 0) die("strtol");

    struct in_addr iaddr;
    switch (inet_pton (AF_INET, host, &iaddr)) {
        case -1:
            die("inet_pton");
        case 0:
            printf("IPv4 domain %s is not parsable\n", host);
            exit(EXIT_FAILURE);
        }
        
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = iaddr,
        .sin_port = htons(port),
    };

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) die("socket");

    printf("Connecting %s port %d\n", inet_ntoa(addr.sin_addr), port);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof addr) == -1)
        die("connect");
    
    // auth
    write(sockfd, argv[3], strlen(argv[3]));
    
    enable_raw_mode(STDOUT_FILENO);
    if (atexit(disable_raw_mode) == -1)
        die("atexit");
#define BUF_SIZE 256
    char buf[BUF_SIZE];

    while (1) {
        fd_set inFds;
        FD_ZERO(&inFds);
        FD_SET(STDIN_FILENO, &inFds);
        FD_SET(sockfd, &inFds);

        if (select(sockfd + 1, &inFds, NULL, NULL, NULL) == -1)
            die("select");

        if (FD_ISSET(STDIN_FILENO, &inFds)) {
            ssize_t numRead = read(STDIN_FILENO, buf, BUF_SIZE);
            if (numRead <= 0)
                exit(EXIT_SUCCESS);

            if (write(sockfd, buf, numRead) != numRead)
                die("partial/failed write");
        }

        if (FD_ISSET(sockfd, &inFds)) {
            ssize_t numRead = read(sockfd, buf, BUF_SIZE);
            if (numRead <= 0)
                exit(EXIT_SUCCESS);

            if (write(STDOUT_FILENO, buf, numRead) != numRead)
                die("partial/failed write");
        }
    }
} 
