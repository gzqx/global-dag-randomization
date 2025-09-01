#include <stdio.h>
#include <omp.h>

void some_function() {
    printf("Entering some_function.\n");
    int i;
    #pragma omp for
    for (i = 0; i < 4; i++) {
        printf("  Inner loop, iteration %d, thread %d\n", i, omp_get_thread_num()); }
    printf("Exiting some_function.\n");
}

int main(int argc, char* argv[]) {
    printf("Starting main program.\n");
    #pragma omp parallel
    {
        int i;
        #pragma omp for
        for (i = 0; i < 8; i++) {
            printf("Main loop 1, iteration %d, thread %d\n", i, omp_get_thread_num()); }
        some_function();
    }
    printf("Main program finished.\n");
    return 0;
}
