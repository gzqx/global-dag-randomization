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

// --- Private Helper: _check_threat_in_timeline ---
bool ThreatAnalyzer::_check_threat_in_timeline(
    const std::vector<DagSim::SimulationEvent>& timeline,
    const DagParser::DAGTask& simulated_dag_structure, // The DAG whose timeline this is
    int vulnerable_subtask_original_dot_id,
    const DagParser::SubTask& vulnerable_subtask_params, // For Δs and Cα
    DagParser::AttackType attack_type_to_evaluate,
    const std::set<std::pair<int, int>>& attacker_subtask_identifiers, // Original {0, subtask_idx}
    const DagParser::DAGTask& original_dag_for_ids // To get attacker original_dot_ids
) {
    double vul_actual_start_time = -1.0;
    double vul_actual_end_time = -1.0;

    // Find execution of the original vulnerable subtask in the timeline
    // The timeline events have subtask_id which is the index in simulated_dag_structure.nodes
    for (size_t aug_idx = 0; aug_idx < simulated_dag_structure.nodes.size(); ++aug_idx) {
        if (simulated_dag_structure.nodes[aug_idx].original_dot_id == vulnerable_subtask_original_dot_id) {
            for (const auto& event : timeline) {
                if (event.subtask_id == simulated_dag_structure.nodes[aug_idx].id) {
                    if (event.type == DagSim::EventType::START) vul_actual_start_time = event.timestamp;
                    if (event.type == DagSim::EventType::FINISH) vul_actual_end_time = event.timestamp;
                }
            }
            break;
        }
    }

    if (vul_actual_start_time < 0 || vul_actual_end_time < 0) {
        return false; // Vulnerable subtask didn't run/finish, no threat possible this way
    }

    std::vector<std::pair<double, double>> vulnerable_windows =
        ThreatAnalyzer::calculate_vulnerable_window(
            attack_type_to_evaluate,
            vul_actual_start_time, vul_actual_end_time,
            vulnerable_subtask_params.delta_minus, vulnerable_subtask_params.delta_plus
        );

    if (vulnerable_windows.empty()) {
        return false;
    }

    for (const auto& att_id_pair : attacker_subtask_identifiers) {
        int original_attacker_subtask_idx = att_id_pair.second;
        int original_attacker_subtask_dot_id = original_dag_for_ids.nodes[original_attacker_subtask_idx].original_dot_id;
        double attacker_execution_in_window = 0.0;

        for (size_t aug_idx = 0; aug_idx < simulated_dag_structure.nodes.size(); ++aug_idx) {
            if (simulated_dag_structure.nodes[aug_idx].original_dot_id == original_attacker_subtask_dot_id) {
                double att_start = -1.0, att_end = -1.0;
                for (const auto& event : timeline) {
                    if (event.subtask_id == simulated_dag_structure.nodes[aug_idx].id) {
                        if (event.type == DagSim::EventType::START) att_start = event.timestamp;
                        if (event.type == DagSim::EventType::FINISH) att_end = event.timestamp;
                    }
                }
                if (att_start >= 0 && att_end >= 0) {
                    for (const auto& window : vulnerable_windows) {
                        double overlap_start = std::max(att_start, window.first);
                        double overlap_end = std::min(att_end, window.second);
                        if (overlap_end > overlap_start) {
                            attacker_execution_in_window += (overlap_end - overlap_start);
                        }
                    }
                }
                break;
            }
        }
        if (attacker_execution_in_window >= vulnerable_subtask_params.c_alpha_requirement) {
            return true; // Threat occurred
        }
    }
    return false; // No threat from any attacker
}


// --- Private Helper: _estimate_threat_for_dag_config ---
double ThreatAnalyzer::_estimate_threat_for_dag_config(
    const DagParser::SubTask& vulnerable_subtask_ref, // From original DAG
    DagParser::AttackType attack_type_to_evaluate,
    const std::set<std::pair<int, int>>& attacker_subtask_identifiers,
    DagParser::DAGTask& base_dag, // The original DAG, non-const for fake param regen
    bool use_augmentation,
    int num_cores,
    int num_simulation_runs,
    std::mt19937& rng,
    DagSim::DagSimulator& simulator)
{
    int threat_occurred_count = 0;
    int vulnerable_subtask_original_dot_id = vulnerable_subtask_ref.original_dot_id;

    for (int run = 0; run < num_simulation_runs; ++run) {
        DagParser::DAGTask dag_to_simulate; // This will be either original (copy) or augmented

        if (use_augmentation) {
            bool params_ok = base_dag.generate_fake_params(num_cores, rng);
            if (!params_ok) { /* std::cerr << ...; */ continue; }
            try {
                dag_to_simulate = base_dag.create_augmented_graph_step1();
            } catch (const std::exception& e) { /* std::cerr << ...; */ continue; }
        } else {
            // Simulate a fresh copy of the base_dag (original)
            dag_to_simulate = base_dag; // Copy constructor
            for(auto& node : dag_to_simulate.nodes) { // Reset state for this run
                node.reset_simulation_state();
            }
        }

        if (dag_to_simulate.nodes.empty()) { /* std::cerr << ...; */ continue; }

        std::vector<DagSim::SimulationEvent> timeline;
        try {
            timeline = simulator.simulate_single_instance(dag_to_simulate, num_cores);
        } catch (const std::exception& e) { /* std::cerr << ...; */ continue; }

        if (_check_threat_in_timeline(
                timeline, dag_to_simulate,
                vulnerable_subtask_original_dot_id, vulnerable_subtask_ref,
                attack_type_to_evaluate, attacker_subtask_identifiers,
                base_dag // Pass original DAG for attacker ID lookup
            )) {
            threat_occurred_count++;
        }
    }
    return static_cast<double>(threat_occurred_count) / num_simulation_runs;
}


// --- Public Method: calculate_comparative_TH ---
ThreatAnalysisResult ThreatAnalyzer::calculate_comparative_TH(
    const DagParser::TaskSet& taskset,
    int vp, int ap, double tp,
    DagParser::AttackType attack_type_to_evaluate,
    int num_cores, // This is 'm'
    int num_simulation_runs_per_estimation,
    unsigned int seed)
{
    if (taskset.tasks.size() != 1) {
        throw std::invalid_argument("calculate_comparative_TH expects a taskset with exactly one DAG.");
    }
    // Work on a copy to mark vulnerable/attacker tasks without modifying the input taskset
    DagParser::DAGTask original_dag_copy = taskset.tasks[0];

    std::mt19937 rng(seed);
    DagSim::DagSimulator simulator; // Create one simulator for all runs

    // Mark vulnerable and attacker subtasks ONCE on the original_dag_copy
    original_dag_copy.mark_subtasks_randomly(vp, ap, rng);

    std::set<std::pair<int, int>> all_vulnerable_subtasks_in_dag;
    for(size_t i=0; i < original_dag_copy.nodes.size(); ++i) {
        if(original_dag_copy.nodes[i].is_vulnerable) {
            all_vulnerable_subtasks_in_dag.insert({0, static_cast<int>(i)});
        }
    }
    std::set<std::pair<int, int>> all_attacker_subtasks_in_dag;
     for(size_t i=0; i < original_dag_copy.nodes.size(); ++i) {
        if(original_dag_copy.nodes[i].is_attacker_controlled) {
            all_attacker_subtasks_in_dag.insert({0, static_cast<int>(i)});
        }
    }

    if (all_vulnerable_subtasks_in_dag.empty()) {
        return {0.0, 0.0};
    }

    // --- Calculate Product Term for Original DAG ---
    double product_term_original = 1.0;
    for (const auto& vul_id_pair : all_vulnerable_subtasks_in_dag) {
        int vul_subtask_original_idx = vul_id_pair.second;
        const DagParser::SubTask& vulnerable_subtask_ref = original_dag_copy.nodes[vul_subtask_original_idx];

        double th_orig = _estimate_threat_for_dag_config(
            vulnerable_subtask_ref, attack_type_to_evaluate, all_attacker_subtasks_in_dag,
            original_dag_copy, false, // use_augmentation = false
            num_cores, num_simulation_runs_per_estimation, rng, simulator
        );
        double effective_threat_orig = epsilon_threshold(th_orig, tp);
        product_term_original *= (1.0 - effective_threat_orig);
        if (product_term_original < 1e-12) { product_term_original = 0.0; break; }
    }

    // --- Calculate Product Term for Augmented DAG ---
    double product_term_augmented = 1.0;
    // original_dag_copy will be modified by generate_fake_params, so it's fine to pass it
    // as it's already a copy of the taskset's DAG.
    for (const auto& vul_id_pair : all_vulnerable_subtasks_in_dag) {
        int vul_subtask_original_idx = vul_id_pair.second;
        const DagParser::SubTask& vulnerable_subtask_ref = original_dag_copy.nodes[vul_subtask_original_idx];

        double th_aug = _estimate_threat_for_dag_config(
            vulnerable_subtask_ref, attack_type_to_evaluate, all_attacker_subtasks_in_dag,
            original_dag_copy, true, // use_augmentation = true
            num_cores, num_simulation_runs_per_estimation, rng, simulator
        );
        double effective_threat_aug = epsilon_threshold(th_aug, tp);
        product_term_augmented *= (1.0 - effective_threat_aug);
        if (product_term_augmented < 1e-12) { product_term_augmented = 0.0; break; }
    }

    ThreatAnalysisResult result;
    result.th_original_dag = std::max(0.0, std::min(1.0, 1.0 - product_term_original));
    result.th_augmented_dag = std::max(0.0, std::min(1.0, 1.0 - product_term_augmented));

    return result;
}

} // namespace DagThreat
