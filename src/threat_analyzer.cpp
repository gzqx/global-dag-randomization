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
    // Note: The definition in the paper seems reversed for probability.
    // If 'value' is the non-threat probability (1-th), and tp is the threat threshold,
    // then we want ε_tp(1-th).
    // Let's implement ε_tp(y) directly as defined:
    // return (value <= threshold_tp) ? 0.0 : value;

    // --- Interpretation based on TH(T) formula ---
    // The formula is TH(T) = 1 - Π ε_tp(1 - th).
    // Here, the argument to ε is (1 - th), the probability of *not* being threatened.
    // If the *threat* probability 'th' is <= tp, then (1-th) >= (1-tp).
    // If the threat 'th' exceeds 'tp', then (1-th) < (1-tp).
    // The epsilon function seems intended to zero out the contribution if the
    // threat is below the threshold tp.
    // Let y = (1 - th). We want ε_tp(y).
    // If th <= tp, then y >= 1-tp. We want the product term to be y = 1-th.
    // If th > tp, then y < 1-tp. We want the product term to be reduced, maybe to 1-tp?
    // The definition ε_tp(y) = 0 if y <= x doesn't seem right in this context.

    // --- Re-interpreting ε based on likely intent ---
    // Let's assume ε_tp operates on the *threat* probability 'th' itself,
    // and the formula meant something like: TH = 1 - Π (1 - ε'_tp(th))
    // where ε'_tp(th) = 0 if th <= tp, and th if th > tp.
    // OR, let's assume the formula is correct: TH = 1 - Π ε_tp(1 - th)
    // and ε_tp(y) should be: y if y >= 1-tp (i.e., th <= tp),
    // and maybe 1-tp (or some other value) if y < 1-tp (i.e., th > tp)?

    // --- Sticking to the formula as written, but adjusting epsilon interpretation ---
    // Let y = 1 - th (the non-threat probability)
    // Let x = tp (the threat threshold)
    // We want ε_tp(y).
    // If the threat 'th' is acceptable (th <= tp), then y >= 1-tp. We keep the non-threat prob y.
    // If the threat 'th' is unacceptable (th > tp), then y < 1-tp. We want to penalize this.
    // Setting ε_tp(y) = 0 when y < 1-tp would maximize TH, which seems wrong.
    // Setting ε_tp(y) = 1-tp when y < 1-tp seems plausible - it uses the threshold value.

    // Let's implement the interpretation: Keep non-threat prob if threat <= tp, otherwise use 1-tp.
    double non_threat_prob = value; // Input 'value' is assumed to be (1 - th)
    double implied_threat_prob = 1.0 - non_threat_prob;

    if (implied_threat_prob <= threshold_tp) {
        return non_threat_prob; // Threat is acceptable, use actual non-threat prob
    } else {
        // Threat is unacceptable, use the threshold non-threat probability
        // This prevents one very high threat probability from making TH=1 immediately.
        return 1.0 - threshold_tp;
    }
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


// --- Placeholder for Threat Probability Estimation ---
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
        return 0.0; // No tasks, no threat
    }

    int n_total_tasks = taskset.tasks.size();
    if (vp > n_total_tasks || ap > n_total_tasks) {
         throw std::invalid_argument("vp or ap exceeds total number of tasks.");
    }

    std::mt19937 rng(seed); // Initialize random number generator

    // 1. Select Vulnerable and Attacker Task Sets (Indices)
    std::set<int> vulnerable_task_indices = select_random_task_indices(n_total_tasks, vp, rng);
    std::set<int> attacker_task_indices = select_random_task_indices(n_total_tasks, ap, rng);
    // Note: Vulnerable and Attacker sets might overlap, which is allowed by the model.

    // 2. Get corresponding Subtask Sets (Indices as pairs {task_idx, subtask_idx})
    std::set<std::pair<int, int>> vulnerable_subtasks = get_subtask_indices(vulnerable_task_indices, taskset);
    std::set<std::pair<int, int>> attacker_subtasks = get_subtask_indices(attacker_task_indices, taskset);

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

        // Calculate non-threat probability
        double non_threat_prob = 1.0 - th;

        // Apply epsilon threshold function
        double epsilon_result = epsilon_threshold(non_threat_prob, tp);

        // Multiply into the product term
        product_term *= epsilon_result;

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
