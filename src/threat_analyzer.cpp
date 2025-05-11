#include "threat_analyzer.h"
#include "dag_task.h"
#include "dag_simulator.h" // For DagSimulator
#include "simulation_event.h" // For SimulationEvent
#include <vector>
#include <set>
#include <map> // For mapping original_dot_id to execution times
#include <numeric>
#include <random>
#include <cmath>
#include <stdexcept>
#include <iostream>
#include <algorithm>

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
    int vulnerable_task_idx, // Should be 0
    int vulnerable_subtask_original_idx,
    const DagParser::SubTask& vulnerable_subtask_ref, // Contains Δ⁻, Δ⁺, Cα
    DagParser::AttackType attack_type_to_evaluate,
    const std::set<std::pair<int, int>>& attacker_subtask_identifiers, // Original {0, subtask_idx}
    DagParser::DAGTask& original_dag, // Pass by non-const ref
    int num_cores,
    int num_simulation_runs,
    std::mt19937& rng)
{
    if (num_simulation_runs <= 0) return 0.0;
    if (vulnerable_task_idx != 0) {
        // This function is now designed for a single DAG context
        throw std::logic_error("estimate_threat_probability called with vulnerable_task_idx != 0 in single DAG mode.");
    }

    int threat_occurred_count = 0;
    DagSim::DagSimulator simulator; // Create one simulator instance

    int vulnerable_subtask_dot_id = vulnerable_subtask_ref.original_dot_id;

    for (int run = 0; run < num_simulation_runs; ++run) {
        // 1. Regenerate Fake Task Parameters for the original_dag
        bool params_ok = original_dag.generate_fake_params(num_cores, rng); // Uses its internal rng or needs one passed
        if (!params_ok) {
            std::cerr << "Warning: Run " << run << ": Failed to generate fake params. Skipping run." << std::endl;
            continue;
        }

        // 2. Create Augmented Graph
        DagParser::DAGTask augmented_dag;
        try {
            augmented_dag = original_dag.create_augmented_graph_step1();
        } catch (const std::exception& e) {
            std::cerr << "Warning: Run " << run << ": Failed to create augmented graph: " << e.what() << ". Skipping run." << std::endl;
            continue;
        }
        if (augmented_dag.nodes.empty()) {
            std::cerr << "Warning: Run " << run << ": Augmented graph is empty. Skipping run." << std::endl;
            continue;
        }


        // 3. Simulate Augmented Graph
        std::vector<DagSim::SimulationEvent> timeline;
        try {
            timeline = simulator.simulate_single_instance(augmented_dag, num_cores);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Run " << run << ": Simulation of augmented graph failed: " << e.what() << ". Skipping run." << std::endl;
            continue;
        }

        // 4. Find execution of the original vulnerable subtask in the augmented timeline
        double vul_actual_start_time = -1.0;
        double vul_actual_end_time = -1.0;

        for (size_t aug_idx = 0; aug_idx < augmented_dag.nodes.size(); ++aug_idx) {
            if (augmented_dag.nodes[aug_idx].original_dot_id == vulnerable_subtask_dot_id) {
                // Find its START and FINISH events in the timeline
                for (const auto& event : timeline) {
                    if (event.subtask_id == augmented_dag.nodes[aug_idx].id) { // event.subtask_id is augmented index
                        if (event.type == DagSim::EventType::START) vul_actual_start_time = event.timestamp;
                        if (event.type == DagSim::EventType::FINISH) vul_actual_end_time = event.timestamp;
                    }
                }
                break; // Found the original vulnerable subtask
            }
        }

        if (vul_actual_start_time < 0 || vul_actual_end_time < 0) {
            // std::cerr << "Warning: Run " << run << ": Vulnerable subtask (dot_id " << vulnerable_subtask_dot_id
            //           << ") did not execute or complete in simulation. Skipping threat check for this run." << std::endl;
            continue;
        }

        // 5. Calculate Vulnerable Window for the specified attack_type
        std::vector<std::pair<double, double>> vulnerable_windows =
            ThreatAnalyzer::calculate_vulnerable_window(
                attack_type_to_evaluate,
                vul_actual_start_time,
                vul_actual_end_time,
                vulnerable_subtask_ref.delta_minus,
                vulnerable_subtask_ref.delta_plus
            );

        if (vulnerable_windows.empty()) {
            continue; // No window, no threat possible for this run
        }

        // 6. Check attacker execution within these windows
        bool threat_this_run = false;
        for (const auto& att_id_pair : attacker_subtask_identifiers) {
            // att_id_pair is {0, original_attacker_subtask_idx}
            int original_attacker_subtask_dot_id = original_dag.nodes[att_id_pair.second].original_dot_id;
            double attacker_execution_in_window = 0.0;

            // Find this attacker subtask in the augmented graph and its execution
            for (size_t aug_idx = 0; aug_idx < augmented_dag.nodes.size(); ++aug_idx) {
                if (augmented_dag.nodes[aug_idx].original_dot_id == original_attacker_subtask_dot_id) {
                    double att_start = -1.0, att_end = -1.0;
                    for (const auto& event : timeline) {
                        if (event.subtask_id == augmented_dag.nodes[aug_idx].id) {
                            if (event.type == DagSim::EventType::START) att_start = event.timestamp;
                            if (event.type == DagSim::EventType::FINISH) att_end = event.timestamp;
                        }
                    }

                    if (att_start >= 0 && att_end >= 0) {
                        // Calculate overlap
                        for (const auto& window : vulnerable_windows) {
                            double overlap_start = std::max(att_start, window.first);
                            double overlap_end = std::min(att_end, window.second);
                            if (overlap_end > overlap_start) {
                                attacker_execution_in_window += (overlap_end - overlap_start);
                            }
                        }
                    }
                    break; // Found this attacker subtask
                }
            }

            if (attacker_execution_in_window >= vulnerable_subtask_ref.c_alpha_requirement) {
                threat_this_run = true;
                break; // One attacker succeeded, threat occurred for this run
            }
        }

        if (threat_this_run) {
            threat_occurred_count++;
        }
    } // End simulation runs loop

    return static_cast<double>(threat_occurred_count) / num_simulation_runs;
}


// --- Calculate TH (Definition 3.7) ---
double ThreatAnalyzer::calculate_TH(
    const DagParser::TaskSet& taskset,
    int vp, int ap, double tp,
    DagParser::AttackType attack_type_to_evaluate,
    int num_simulation_runs, // This is N for the inner loop
    unsigned int seed)
{
    // ... (parameter validation) ...
    if (taskset.tasks.size() != 1) {
        throw std::invalid_argument("calculate_TH (single DAG mode) expects a taskset with exactly one DAG.");
    }
    DagParser::DAGTask original_dag = taskset.tasks[0]; // Work on a copy for marking


    std::mt19937 rng(seed);

    // Mark vulnerable and attacker subtasks ONCE at the beginning on the original_dag copy
    original_dag.mark_subtasks_randomly(vp, ap, rng); // This sets is_vulnerable, is_attacker, Δs, Cα

    std::set<std::pair<int, int>> all_vulnerable_subtasks_in_dag;
    for(size_t i=0; i < original_dag.nodes.size(); ++i) {
        if(original_dag.nodes[i].is_vulnerable) {
            all_vulnerable_subtasks_in_dag.insert({0, static_cast<int>(i)});
        }
    }
    std::set<std::pair<int, int>> all_attacker_subtasks_in_dag;
     for(size_t i=0; i < original_dag.nodes.size(); ++i) {
        if(original_dag.nodes[i].is_attacker_controlled) {
            all_attacker_subtasks_in_dag.insert({0, static_cast<int>(i)});
        }
    }

    if (all_vulnerable_subtasks_in_dag.empty()) {
        return 0.0;
    }

    double product_term = 1.0;

    for (const auto& vul_id_pair : all_vulnerable_subtasks_in_dag) {
        // vul_id_pair is {0, original_subtask_idx}
        int vul_subtask_original_idx = vul_id_pair.second;
        const DagParser::SubTask& vulnerable_subtask_ref = original_dag.nodes[vul_subtask_original_idx];

        // Estimate threat probability for this specific vulnerable subtask
        double th = estimate_threat_probability(
            0, // vulnerable_task_idx is always 0
            vul_subtask_original_idx,
            vulnerable_subtask_ref,
            attack_type_to_evaluate, // Pass the chosen attack type
            all_attacker_subtasks_in_dag,
            original_dag, // Pass the original_dag (which will have its fake params regenerated inside)
            original_dag.get_required_cores() > 0 ? original_dag.get_required_cores() : 1, // Use parsed cores or 1
            num_simulation_runs,
            rng // Pass the RNG
        );

        double effective_threat = epsilon_threshold(th, tp);
        product_term *= (1.0 - effective_threat);

        if (product_term < 1e-12) { product_term = 0.0; break; }
    }

    double th_result = 1.0 - product_term;
    return std::max(0.0, std::min(1.0, th_result));
}

std::vector<std::pair<double, double>> ThreatAnalyzer::calculate_vulnerable_window(
    DagParser::AttackType attack_type,
    double subtask_sim_start_time, // t_s(τ)
    double subtask_sim_end_time,   // t_e(τ)
    double delta_minus,            // Δ⁻(τ)
    double delta_plus              // Δ⁺(τ)
) {
    std::vector<std::pair<double, double>> windows;

    if (subtask_sim_start_time < 0 || subtask_sim_end_time < 0 || subtask_sim_start_time > subtask_sim_end_time) {
        // Invalid simulation times, return empty window
        // Or throw an error, depending on desired strictness
        std::cerr << "Warning: Invalid simulation times for vulnerable window calculation: start="
                  << subtask_sim_start_time << ", end=" << subtask_sim_end_time << std::endl;
        return windows;
    }

    // Ensure deltas are non-negative
    delta_minus = std::max(0.0, delta_minus);
    delta_plus  = std::max(0.0, delta_plus);

    switch (attack_type) {
        case DagParser::AttackType::ANTERIOR:
            // [t_s(τ) - Δ⁻(τ), t_s(τ)]
            // Ensure start of window is not negative
            windows.push_back({std::max(0.0, subtask_sim_start_time - delta_minus), subtask_sim_start_time});
            break;

        case DagParser::AttackType::POSTERIOR:
            // [t_e(τ), t_e(τ) + Δ⁺(τ)]
            windows.push_back({subtask_sim_end_time, subtask_sim_end_time + delta_plus});
            break;

        case DagParser::AttackType::PINCER_SINGLE_WINDOW: // Assuming C_alpha is for the combined duration
        case DagParser::AttackType::PINCER_DUAL_WINDOW:   // Or if C_alpha is split
            // [t_s(τ) - Δ⁻(τ), t_s(τ)] U [t_e(τ), t_e(τ) + Δ⁺(τ)]
            windows.push_back({std::max(0.0, subtask_sim_start_time - delta_minus), subtask_sim_start_time});
            windows.push_back({subtask_sim_end_time, subtask_sim_end_time + delta_plus});
            break;

        case DagParser::AttackType::CONCURRENT:
            // [t_s(τ), t_e(τ)]
            windows.push_back({subtask_sim_start_time, subtask_sim_end_time});
            break;

        case DagParser::AttackType::NONE:
        default:
            // No defined window or unknown attack type
            break;
    }

    // Filter out zero-duration or invalid (end < start) windows that might result from t_s=t_e
    windows.erase(std::remove_if(windows.begin(), windows.end(), [](const auto& p){
        return p.second <= p.first; // Remove if end <= start
    }), windows.end());


    return windows;
}

} // namespace DagThreat
