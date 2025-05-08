#include "threat_analyzer.h"
#include "dag_task.h" // Access DAGTask members
#include <vector>
#include <set>
#include <numeric>   // For std::iota
#include <random>    // For std::mt19937, std::shuffle, std::random_device
#include <cmath>     // For std::max
#include <algorithm>
#include <stdexcept>
#include <iostream>  // For warnings/debug

namespace DagThreat {

// --- Epsilon Threshold Function ---
double ThreatAnalyzer::epsilon_threshold(double value, double threshold_tp) {
        // Definition 3.6: ε_tp(y) = 0 if y <= tp, else y
    // Input 'value' is the threat probability 'th'
    // Input 'threshold_tp' is the threshold 'tp'
    return (value <= threshold_tp) ? 0.0 : value;
}


// --- Helper to select random task indices ---
std::set<int> ThreatAnalyzer::select_random_task_indices(int total_tasks, int count, std::mt19937& rng) {
    if (count < 0 || count > total_tasks) {
        throw std::invalid_argument("Invalid count for random selection.");
    }
    std::set<int> selected_indices;
    if (count == 0) {
        return selected_indices;
    }

    std::vector<int> all_indices(total_tasks);
    std::iota(all_indices.begin(), all_indices.end(), 0); // Fill with 0, 1, ..., total_tasks-1
    std::shuffle(all_indices.begin(), all_indices.end(), rng);

    for (int i = 0; i < count; ++i) {
        selected_indices.insert(all_indices[i]);
    }
    return selected_indices;
}

// --- Helper to get subtask indices ---
std::set<std::pair<int, int>> ThreatAnalyzer::get_subtask_indices(
    const std::set<int>& task_indices,
    const DagParser::TaskSet& taskset)
{
    std::set<std::pair<int, int>> subtask_indices;
    for (int task_idx : task_indices) {
        if (task_idx < 0 || task_idx >= taskset.tasks.size()) {
            std::cerr << "Warning: Invalid task index " << task_idx << " provided." << std::endl;
            continue;
        }
        const auto& task = taskset.tasks[task_idx];
        for (size_t subtask_idx = 0; subtask_idx < task.nodes.size(); ++subtask_idx) {
            subtask_indices.insert({task_idx, static_cast<int>(subtask_idx)});
        }
    }
    return subtask_indices;
}


// --- Placeholder for Threat Probability Estimation -
double ThreatAnalyzer::estimate_threat_probability(
    int vulnerable_task_idx,
    int vulnerable_subtask_idx,
    const std::set<std::pair<int, int>>& attacker_subtasks,
    const DagParser::TaskSet& taskset,
    int num_simulation_runs)
{
    // ***********************************************************************
    // ********************* PLACEHOLDER IMPLEMENTATION **********************
    // ***********************************************************************
    // This function needs to be replaced with logic that uses the results
    // of 'num_simulation_runs' multi-task simulations.
    //
    // Conceptual Logic:
    // 1. threat_count = 0
    // 2. For run = 1 to num_simulation_runs:
    // 3.   Simulate the system (at least vulnerable_task_idx and all tasks
    //        containing attacker subtasks) with appropriate randomization applied.
    // 4.   Get the resulting timeline for this run.
    // 5.   Find the start/end time of vulnerable_subtask in the timeline.
    // 6.   Define the vulnerable window ν based on start/end times (and Δ parameters - currently undefined).
    // 7.   Define the required attack time C_α (currently undefined).
    // 8.   For each attacker subtask (att_task_idx, att_subtask_idx) in attacker_subtasks:
    // 9.      Calculate the execution time of the attacker subtask within ν in this timeline.
    // 10.     If execution_time > C_α:
    // 11.        threat_count++;
    // 12.        break; // Move to next simulation run
    // 13. Return (double)threat_count / num_simulation_runs;
    // ***********************************************************************

    // Simple Placeholder: Return a dummy value (e.g., 0.1 or based on indices)
    // This allows testing the structure of calculate_TH.
    // DO NOT USE THIS IN PRODUCTION.
    if (attacker_subtasks.empty()) return 0.0; // No attackers, no threat
    // Example dummy: small probability, increases slightly with index
    double base_prob = 0.05;
    double increment = (double)(vulnerable_task_idx + vulnerable_subtask_idx % 10) * 0.001;
    return std::min(1.0, base_prob + increment);
    // return 0.0; // Or just return 0 for testing structure
}


// --- Calculate TH (Definition 3.7) ---
double ThreatAnalyzer::calculate_TH(
    const DagParser::TaskSet& taskset,
    int vp,
    int ap,
    double tp, // Threat probability threshold
    int num_simulation_runs,
    unsigned int seed)
{
    if (vp < 0 || ap < 0 || tp < 0.0 || tp > 1.0 || num_simulation_runs <= 0) {
        throw std::invalid_argument("Invalid parameters for TH calculation.");
    }
    if (taskset.tasks.empty()) {
        // If vp or ap > 0, it's an invalid request for an empty taskset
        if (vp > 0 || ap > 0) {
             throw std::invalid_argument("vp or ap cannot be positive for an empty taskset.");
        }
        return 0.0; // No tasks, no threat
    }

    // --- Calculate TOTAL number of subtasks ---
    size_t n_total_subtasks = 0;
    for (const auto& task : taskset.tasks) {
        n_total_subtasks += task.nodes.size();
    }


    // Compare vp and ap against the total number of subtasks
    if (vp > n_total_subtasks || ap > n_total_subtasks) {
         throw std::invalid_argument("vp or ap exceeds total number of subtasks in the taskset.");
    }
    // --- End Corrected Validation Check ---

    std::mt19937 rng(seed); // Initialize random number generator

 // Create a flat list of all subtasks {task_idx, subtask_idx}
    std::vector<std::pair<int, int>> all_subtasks_flat;
    all_subtasks_flat.reserve(n_total_subtasks);
    for (size_t task_idx = 0; task_idx < taskset.tasks.size(); ++task_idx) {
        for (size_t subtask_idx = 0; subtask_idx < taskset.tasks[task_idx].nodes.size(); ++subtask_idx) {
            all_subtasks_flat.push_back({static_cast<int>(task_idx), static_cast<int>(subtask_idx)});
        }
    }

    // Shuffle the flat list
    std::shuffle(all_subtasks_flat.begin(), all_subtasks_flat.end(), rng);

    // Select the first 'vp' as vulnerable and the first 'ap' as attackers
    // Note: This allows overlap between vulnerable and attacker sets if vp+ap > total,
    //       or even if they just happen to be selected in the shuffle.
    //       The paper doesn't explicitly forbid overlap.
    std::set<std::pair<int, int>> vulnerable_subtasks;
    for (int i = 0; i < vp; ++i) {
        vulnerable_subtasks.insert(all_subtasks_flat[i]);
    }

    std::set<std::pair<int, int>> attacker_subtasks;
    // To avoid selecting the exact same subtasks if vp and ap overlap significantly,
    // we could select from the remaining list, or just select the first 'ap' as below.
    // Let's stick to selecting the first 'ap' for simplicity, allowing overlap.
    for (int i = 0; i < ap; ++i) {
        attacker_subtasks.insert(all_subtasks_flat[i]);
    }
    // --- End Subtask Selection ---


    if (vulnerable_subtasks.empty()) {
        return 0.0; // No vulnerable subtasks selected, TH = 0
    }

    // 3. Calculate Product Term: Π_{τ ∈ T_vul} ε_{tp}(1 - th_{T_att}(τ))
    double product_term = 1.0;

    for (const auto& vul_pair : vulnerable_subtasks) {
        int vul_task_idx = vul_pair.first;
        int vul_subtask_idx = vul_pair.second; // Index within task vul_task_idx

        // Estimate threat probability using the placeholder
        double th = estimate_threat_probability(
            vul_task_idx,
            vul_subtask_idx,
            attacker_subtasks,
            taskset,
            num_simulation_runs
        );

        // Apply epsilon directly to the threat probability 'th'
        double effective_threat = epsilon_threshold(th, tp); // ε_tp(th)

        // Calculate the term for the product: (1 - effective_threat)
        double term = 1.0 - effective_threat;

        // Multiply into the product term
        product_term *= term;

        // Optimization: if product becomes near zero, further multiplication won't change it much
        if (product_term < 1e-12) { // Use a small tolerance
             product_term = 0.0;
             break;
        }
    }

    // 4. Calculate TH(T) = 1 - Product Term
    double th_result = 1.0 - product_term;

    return std::max(0.0, std::min(1.0, th_result)); // Clamp result to [0, 1]
}

} // namespace DagThreat
