#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
#include "dag_simulator.h" // <-- Include simulator
#include "simulation_event.h" // <-- Include event definition
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip> // For formatting output

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_taskset_directory>" << std::endl;
        return 1;
    }
    std::string taskset_dir = argv[1];

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

    if (!load_success) {
         std::cerr << "\nFailed to load taskset completely. Cannot simulate." << std::endl;
         return 1;
    }
    if (loaded_taskset.tasks.empty()) {
         std::cerr << "\nTaskset is empty. Nothing to simulate." << std::endl;
         return 0;
    }

    // --- Simulation ---
    // Simulate only the FIRST DAG in the loaded taskset for this example
    std::cout << "\n--- Simulating First DAG ---" << std::endl;
    DagSim::DagSimulator simulator;
    try {
        // Pass the first task by reference - its state will be modified
        std::vector<DagSim::SimulationEvent> timeline = simulator.simulate_single_instance(loaded_taskset.tasks[0]);

        std::cout << "\n--- Simulation Timeline ---" << std::endl;
        std::cout << std::fixed << std::setprecision(4); // Format time output
        std::cout << "Timestamp | Event  | Subtask | Core" << std::endl;
        std::cout << "----------|--------|---------|-----" << std::endl;
        for (const auto& event : timeline) {
            std::cout << std::setw(9) << event.timestamp << " | "
                      << std::setw(6) << DagSim::eventTypeToString(event.type) << " | "
                      << std::setw(7) << event.subtask_id << " | "
                      << std::setw(4) << event.core_id << std::endl;
        }
         std::cout << "--------------------------" << std::endl;

         // Optional: Print final state of subtasks
         std::cout << "\n--- Final Subtask States ---" << std::endl;
         loaded_taskset.tasks[0].print(); // Will show finish times etc.


    } catch (const std::exception& e) {
        std::cerr << "Simulation failed: " << e.what() << std::endl;
        return 1;
    }


    std::cout << "\nTest finished." << std::endl;
    return 0;
}
