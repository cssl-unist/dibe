#include <stdio.h>
#include <unistd.h>

int foo(int a) {
    return a;
}

int goo(int b) {
    return b+1;
}

int main() {
    int a = 0;
    int b = 0;
    setbuf(stdout, NULL);
    printf("Process ID: %d\n", getpid());

    while(a < 10){
        a = foo(a);
        b = goo(b);
        printf("%d %d\n", a, b);
        sleep(5);
    }

    return 0;
}