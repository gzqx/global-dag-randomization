#ifndef SUB_TASK_H
#define SUB_TASK_H

#include <vector>
#include <iostream>
#include <limits>

namespace DagParser {

    enum class SubTaskState {
        NOT_READY, // Predecessors not complete
        READY,     // Predecessors complete, eligible to run
        RUNNING,   // Currently executing
        FINISHED   // Execution complete
    };

    struct SubTask {
        int id = -1;         // The ID assigned during parsing (usually matches index)
        int original_dot_id = -1; // The ID found in the DOT file label/node definition
        double wcet = 0.0;
        //int core_id = 0;     // Value from 'p=' attribute, defaults to 0 if not present

        // Using indices into the DAGTask's nodes vector for adjacency
        std::vector<int> predecessors;
        std::vector<int> successors;

        // --- Simulation State Variables ---
        SubTaskState state = SubTaskState::NOT_READY;
        double start_time = -1.0;
        double finish_time = -1.0;
        double remaining_wcet = 0.0; // Needed even for non-preemptive to track progress
        int assigned_core = -1;      // Core it's running on or finished on
        int predecessors_finished_count = 0; // Counter for readiness check


        // Basic print for debugging
        void print() const {
            std::cout << "    SubTask (ID: " << id << ", DotID: " << original_dot_id
                << ", WCET: " << wcet << ")\n";
            std::cout << "      Preds: ";
            for(int p : predecessors) std::cout << p << " ";
            std::cout << "\n      Succs: ";
            for(int s : successors) std::cout << s << " ";
            std::cout << std::endl;
        }
        void reset_simulation_state() {
            state = SubTaskState::NOT_READY;
            start_time = -1.0;
            finish_time = -1.0;
            remaining_wcet = wcet; // Reset remaining time
            assigned_core = -1;
            predecessors_finished_count = 0;
            // Initial state depends on predecessors
            if (predecessors.empty()) {
                state = SubTaskState::READY;
            }
        }
    };
} // namespace DagParser

#endif // SUB_TASK_H
