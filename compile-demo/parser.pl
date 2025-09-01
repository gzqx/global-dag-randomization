#!/usr/bin/perl
use strict;
use warnings;

if (@ARGV < 2) {
    die "Usage: ./inject_fakes.pl <input_c_file.c> <budget>\n";
}

my $c_file_path = $ARGV[0];
my $budget      = $ARGV[1];

if ($budget !~ /^\d+$/) {
    die "Error: Budget must be a non-negative integer.\n";
}

# Read C
my $c_code = do {
    local $/ = undef;
    open my $fh, '<', $c_file_path or die "Could not open file '$c_file_path': $!\n";
    <$fh>;
};

# Find openmp pragma
my $num_fake_tasks = () = $c_code =~ /^\s*#pragma\s+omp\s+for/mg;

if ($num_fake_tasks == 0) {
    print STDERR "Warning: No '#pragma omp for' directives found. No changes made.\n";
    print $c_code;
    exit 0;
}

print STDERR "Info: Found $num_fake_tasks parallel for-loops to instrument.\n";


# C snippets
# Header
my @headers_to_add = (
    "#include <stdio.h>",
    "#include <stdlib.h>",
    "#include <time.h>"
);

# Global variables and helper functions
my $global_code = <<"END_GLOBALS";

// --- Injected by Parallel DAG Randomization Script ---
#define MAX_FAKE_TASKS $num_fake_tasks
int fake_wcets[MAX_FAKE_TASKS] = {0};
int fake_task_counter = 0;

// Simple function to simulate a fake task's execution
void run_fake_task(int wcet) {
    if (wcet > 0) {
        printf("--- Fake task starting (WCET = %d) ---\\n", wcet);
        for (int i = 1; i <= wcet; ++i) {
            printf("    Fake job executing second %d...\\n", i);
            // In a real scenario, this would be a busy-wait or sleep.
        }
        printf("--- Fake task finished ---\\n");
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
    printf("--- Budget of %d distributed across %d fake tasks ---\\n", total_budget, num_fakes);
}
// --- End of Injected Code ---

END_GLOBALS

# Algo2 for main()
my $main_init_code = <<"END_MAIN_INIT";
    // Injected: Initialize randomization for this run
    srand(time(NULL));
    distribute_budget($budget, MAX_FAKE_TASKS);
END_MAIN_INIT


# Add necessary headers if they don't exist
my $header_block = "";
for my $header (@headers_to_add) {
    my $header_re = quotemeta($header);
    if ($c_code !~ /$header_re/) {
        $header_block .= "$header\n";
    }
}
$c_code = $header_block . $c_code;


my $last_include_pos = -1;
# Find the end position of the last matching #include line
while ($c_code =~ /^\s*#include.*$/mg) {
    $last_include_pos = pos($c_code);
}

if ($last_include_pos != -1) {
    # Found at least one include. Insert after it.
    my $newline_pos = index($c_code, "\n", $last_include_pos - length($&));
    if ($newline_pos != -1) {
        $last_include_pos = $newline_pos + 1;
    }
    # Rebuild the string with the injected code
    $c_code = substr($c_code, 0, $last_include_pos) . "\n" . $global_code . substr($c_code, $last_include_pos);
} else {
    # No includes found, inject at the very top
    $c_code = $global_code . "\n" . $c_code;
}

# Actual Injection
$c_code =~ s/(int\s+main\s*\([^)]*\)\s*\{)/$1\n$main_init_code/s;

$c_code =~ s/^\s*#pragma\s+omp\s+for/
    "    \/\/ Injected: Run fake task before parallel section\n" .
    "    run_fake_task(fake_wcets[fake_task_counter++]);\n" .
    "    #pragma omp for"
/mge;

print $c_code;
