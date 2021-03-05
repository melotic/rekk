//
// Created by justin on 1/29/21.
//

#include <stdlib.h>
#include <stdio.h>

int compare(int a, int b) {
    if (a == b) {
        return 0;
    }

    if (a > b) {
        return 1;
    } else {
        return -1;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("no args given\n");
        return 1;
    }

    char *num = argv[1];
    char *num2 = argv[2];

    int a = atoi(num);
    int b = atoi(num2);

    printf("cmp:         %d\n", compare(a, b));
    printf("cmp to 0xCC: %d\n", compare(a, 0xCC));
    return 0;
}

