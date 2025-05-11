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

    // --- Enum for Attack Types (as per paper Def 3.1) ---
    // This could be more elaborate if different C_alpha are needed per attack type
    enum class AttackType {
        ANTERIOR,
        POSTERIOR,
        PINCER_SINGLE_WINDOW, // If C_alpha is a single value for PINCER
        PINCER_DUAL_WINDOW,   // If C_alpha has two values for PINCER
        CONCURRENT,
        NONE // Default
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

        // --- New Members for Vulnerability and Attack Analysis ---
        bool is_vulnerable = false;
        bool is_attacker_controlled = false;

        // Vulnerable window parameters (Def 3.1)
        // These are specific to this subtask IF IT IS VULNERABLE.
        // For simplicity, let's assume they are set externally if is_vulnerable is true.
        // We could also have a map if a subtask is vulnerable to multiple attack types with different deltas.
        double delta_minus = 0.0; // Δ⁻(τ)
        double delta_plus = 0.0;  // Δ⁺(τ)

        // Execution time required by an attacker within the vulnerable window (Def 3.3)
        // This could also be a map: std::map<AttackType, double> c_alpha_requirements;
        // For now, a single value for the primary attack type it's vulnerable to.
        double c_alpha_requirement = 0.0;
        // AttackType primary_vulnerable_attack_type = AttackType::NONE; // To specify which C_alpha this is for

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
        // --- New method to reset threat analysis state ---
        void reset_threat_params() {
            is_vulnerable = false;
            is_attacker_controlled = false;
            delta_minus = 0.0;
            delta_plus = 0.0;
            c_alpha_requirement = 0.0;
        }
    };
} // namespace DagParser

#endif // SUB_TASK_H
