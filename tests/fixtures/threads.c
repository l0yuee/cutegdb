/* Fixture for the threads, signals and handles views: two named worker threads, a SIGUSR1
 * handler and an open file descriptor. Runs until killed. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

int shared_value;
int usr1_count;

static void *worker(void *arg)
{
    long id = (long)arg;
    for (;;) {
        shared_value += (int)id;
        usleep(1000);
    }
    return NULL;
}

static void on_usr1(int sig)
{
    (void)sig;
    usr1_count++;
}

int main(int argc, char **argv)
{
    int fd = open(argv[0], O_RDONLY);
    signal(SIGUSR1, on_usr1);

    pthread_t threads[2];
    for (long i = 0; i < 2; i++) {
        char name[16];
        pthread_create(&threads[i], NULL, worker, (void *)(i + 1));
        strcpy(name, i == 0 ? "worker1" : "worker2");
        pthread_setname_np(threads[i], name);
    }
    if (argc > 1 && strcmp(argv[1], "signal") == 0)
        raise(SIGUSR1);

    for (;;) {
        shared_value++;
        usleep(1000);
    }
    close(fd);
    return 0;
}
