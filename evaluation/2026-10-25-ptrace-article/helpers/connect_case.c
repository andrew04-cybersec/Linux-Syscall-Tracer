/*Workload C: attempt a TCP connection to a closed loopback port.*/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);                 /*discard port, expected closed*/
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /*127.0.0.1*/

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 1;
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return rc == 0 ? 0 : 2;
}
