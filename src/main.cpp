#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>

int main(int argc, char* argv[]) {
    // --- Argument Handling ---
    if (argc < 3) { // Now need directory AND number of cores
        std::cerr << "Usage: " << argv[0] << " <path_to_taskset_directory> <num_cores>" << std::endl;
        std::cerr << "Example: " << argv[0] << " ../dags/taskset_0 8" << std::endl;
        return 1;
    }
    std::string taskset_dir = argv[1];
    int num_cores = 0;
    try {
        num_cores = std::stoi(argv[2]);
        if (num_cores <= 0) throw std::invalid_argument("Num cores must be positive");
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid number of cores '" << argv[2] << "'. " << e.what() << std::endl;
        return 1;
    }


    DagParser::TaskSetLoader loader;
    DagParser::TaskSet loaded_taskset;

    std::cout << "Attempting to load taskset from: " << taskset_dir << std::endl;
    bool load_success = false;
    try {
        load_success = loader.load(taskset_dir, loaded_taskset);
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during loading initialization: " << e.what() << std::endl;
        return 1;
    }

    if (!load_success || loaded_taskset.tasks.empty()) {
         std::cerr << "\nFailed to load taskset completely or taskset is empty. Cannot proceed." << std::endl;
         return 1;
    }
     std::cout << "\nSuccessfully loaded taskset." << std::endl;


    // --- Generate Fake Parameters for each DAG ---
    std::cout << "\n--- Generating Fake Parameters (m=" << num_cores << ") ---" << std::endl;
    int success_count = 0;
    for (size_t i = 0; i < loaded_taskset.tasks.size(); ++i) {
        DagParser::DAGTask& current_dag = loaded_taskset.tasks[i];
        std::cout << "--- Processing DAG Index: " << i
                  << " (Source: " << current_dag.source_file_path << ") ---" << std::endl;
        try {
            bool success = current_dag.generate_fake_params(num_cores);
            if (success) {
                std::cout << "  Successfully generated fake parameters." << std::endl;
                // Print the generated fake WCETs (using the updated DAGTask::print)
                // current_dag.print(); // Or just print the map below
                 std::cout << "  Fake Task WCETs (vf(node_index) -> wcet):\n";
                 if (current_dag.fake_task_wcets.empty()) {
                      std::cout << "    (No fake tasks needed/generated)\n";
                 } else {
                     for(const auto& pair : current_dag.fake_task_wcets) {
                         std::cout << "    vf(" << pair.first << ") -> " << pair.second << "\n";
                     }
                 }
                success_count++;
            } else {
                std::cout << "  Failed to generate fake parameters (likely negative budget)." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "  Error generating fake parameters for DAG " << i << ": " << e.what() << std::endl;
        }
         std::cout << "------------------------------------------" << std::endl;
    }

    std::cout << "\nFinished generating fake parameters for "
              << success_count << "/" << loaded_taskset.tasks.size() << " DAGs." << std::endl;


    // --- Optional: Print final TaskSet structure ---
    // std::cout << "\n--- Final TaskSet Structure ---" << std::endl;
    // loaded_taskset.print();


    std::cout << "\nTest finished." << std::endl;
    return 0;
}
