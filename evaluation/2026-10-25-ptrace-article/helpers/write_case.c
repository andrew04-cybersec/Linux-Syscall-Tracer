/*Workload B: create a test file in /tmp and write a fixed payload.*/
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *payload = "FORENSICS_TEST_2026\n";
    int fd = open("/tmp/tracer_case_study.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return 1;
    if (write(fd, payload, strlen(payload)) < 0)
        return 1;
    close(fd);
    return 0;
}
