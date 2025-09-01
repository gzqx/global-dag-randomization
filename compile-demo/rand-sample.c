#include <stdlib.h>
#include <time.h>
#include <stdio.h>


// --- Injected by Parallel DAG Randomization Script ---
#define MAX_FAKE_TASKS 2
int fake_wcets[MAX_FAKE_TASKS] = {0};
int fake_task_counter = 0;

// Simple function to simulate a fake task's execution
void run_fake_task(int wcet) {
    if (wcet > 0) {
        printf("--- Fake task starting (WCET = %d) ---\n", wcet);
        for (int i = 1; i <= wcet; ++i) {
            printf("    Fake job executing second %d...\n", i);
            // In a real scenario, this would be a busy-wait or sleep.
        }
        printf("--- Fake task finished ---\n");
    }
}

// Distributes the budget randomly among the fake tasks
void distribute_budget(int total_budget, int num_fakes) {
    if (num_fakes <= 0) return;
    
    fake_task_counter = 0;
    for (int i = 0; i < num_fakes; ++i) {
        fake_wcets[i] = 0;
    }

    for (int i = 0; i < total_budget; ++i) {
        fake_wcets[rand() % num_fakes]++;
    }
    printf("--- Budget of %d distributed across %d fake tasks ---\n", total_budget, num_fakes);
}
// --- End of Injected Code ---

#include <omp.h>

void some_function() {
    printf("Entering some_function.\n");
    int i;
    // Injected: Run fake task before parallel section
    run_fake_task(fake_wcets[fake_task_counter++]);
    #pragma omp for
    for (i = 0; i < 4; i++) {
        printf("  Inner loop, iteration %d, thread %d\n", i, omp_get_thread_num()); }
    printf("Exiting some_function.\n");
}

int main(int argc, char* argv[]) {
    // Injected: Initialize randomization for this run
    srand(time(NULL));
    distribute_budget(10, MAX_FAKE_TASKS);

    printf("Starting main program.\n");
    #pragma omp parallel
    {
        int i;
    // Injected: Run fake task before parallel section
    run_fake_task(fake_wcets[fake_task_counter++]);
    #pragma omp for
        for (i = 0; i < 8; i++) {
            printf("Main loop 1, iteration %d, thread %d\n", i, omp_get_thread_num()); }

        // Some other work could be here

        some_function();
    }
    printf("Main program finished.\n");
    return 0;
}
