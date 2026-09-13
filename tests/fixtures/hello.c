#include <stdio.h>
#include <unistd.h>

int counter;

static int add(int a, int b)
{
    return a + b;
}

int main(int argc, char **argv)
{
    int x = add(2, 3);
    printf("x=%d\n", x);
    if (argc > 1) {
        for (;;) {
            counter++;
            usleep(1000);
        }
    }
    return x - 5;
}
