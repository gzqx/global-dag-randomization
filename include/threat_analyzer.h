#ifndef THREAT_ANALYZER_H
#define THREAT_ANALYZER_H

#include "taskset.h" // Needs access to the full taskset
#include <vector>
#include <set>
#include <string>
#include <random>
#include <utility> // For std::pair

namespace DagSim { class DagSimulator; } // Forward declaration

namespace DagThreat { // New namespace for threat analysis

class ThreatAnalyzer {
public:
    struct ThreatParams {
        double delta_minus = 0.0; // Δ⁻(τ): Time before start for vulnerable window
        double delta_plus = 0.0;  // Δ⁺(τ): Time after end for vulnerable window
        double attack_wcet_threshold = 1.0; // C_α(τ): WCET needed by attacker in window
                                            // Add other parameters if needed (e.g., which attack type 'alpha' from Def 3.1)
    };
    // Constructor - potentially store references or configuration if needed
    ThreatAnalyzer() = default;

    // Calculates the Partitioned System Threat with Threshold (Definition 3.7)
    // taskset: The complete taskset definition.
    // vp: Number of vulnerable tasks to select randomly.
    // ap: Number of attacker-controlled tasks to select randomly.
    // tp: Threat probability threshold for epsilon function.
    // num_simulation_runs: The number of simulation runs used to estimate each 'th' probability.
    // seed: Optional seed for random selection reproducibility.
    double calculate_TH(
        const DagParser::TaskSet& taskset,
        int vp,
        int ap,
        double tp,
        DagParser::AttackType attack_type_to_evaluate, // <-- ADDED parameter
        int num_simulation_runs,
        //const ThreatParams& threat_params, // Pass threat definition parameters
        unsigned int seed = std::random_device{}()
    );
    static std::vector<std::pair<double, double>> calculate_vulnerable_window(
        DagParser::AttackType attack_type,
        double subtask_sim_start_time, // t_s(τ) from simulation
        double subtask_sim_end_time,   // t_e(τ) from simulation
        double delta_minus,            // Δ⁻(τ)
        double delta_plus              // Δ⁺(τ)
    );

private:
    // Placeholder function to estimate the threat probability th_{T_att}(τ_vul)
    // This function would normally involve running 'num_simulation_runs' multi-task simulations.
    // It needs to know which subtask is vulnerable and the set of all attacker subtasks.
    // Returns the estimated probability (0.0 to 1.0).
    double estimate_threat_probability(
        int vulnerable_task_idx,         // Will always be 0 for single DAG
        int vulnerable_subtask_original_idx, // Index of τ_vul in original_dag.nodes
        const DagParser::SubTask& vulnerable_subtask_ref, // Reference to the original vulnerable subtask
        DagParser::AttackType attack_type_to_evaluate, // The specific attack type
        const std::set<std::pair<int, int>>& attacker_subtask_identifiers, // Original {task_idx, subtask_idx}
        DagParser::DAGTask& original_dag, // The single DAG (non-const to allow regen of fake params)
        int num_cores,                    // Number of cores for simulation
        int num_simulation_runs,
        std::mt19937& rng                 // Pass RNG for fake param regeneration
    );
    // Epsilon threshold function (Definition 3.6)
    double epsilon_threshold(double value, double threshold_tp);

    // Helper to select random task indices without replacement
    std::set<int> select_random_task_indices(int total_tasks, int count, std::mt19937& rng);

    // Helper to get all subtask indices for a set of task indices
    // Returns set of pairs {task_index, subtask_index_within_task}
    std::set<std::pair<int, int>> get_subtask_indices(
        const std::set<int>& task_indices,
        const DagParser::TaskSet& taskset);

};

} // namespace DagThreat

#endif // THREAT_ANALYZER_H
