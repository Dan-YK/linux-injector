#include <stdio.h>

__attribute__((constructor)) void init() {
    printf("Injected!\n");
}
