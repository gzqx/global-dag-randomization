#ifndef THREAT_ANALYZER_H
#define THREAT_ANALYZER_H

#include "taskset.h" // Needs access to the full taskset
#include <vector>
#include <set>
#include <string>
#include <random>

namespace DagThreat { // New namespace for threat analysis

class ThreatAnalyzer {
public:
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
        int num_simulation_runs,
        unsigned int seed = std::random_device{}() // Use random_device by default
    );

private:
    // Placeholder function to estimate the threat probability th_{T_att}(τ_vul)
    // This function would normally involve running 'num_simulation_runs' multi-task simulations.
    // It needs to know which subtask is vulnerable and the set of all attacker subtasks.
    // Returns the estimated probability (0.0 to 1.0).
    double estimate_threat_probability(
        int vulnerable_task_idx,         // Index of the task containing τ_vul
        int vulnerable_subtask_idx,      // Index of τ_vul within its task's nodes vector
        const std::set<std::pair<int, int>>& attacker_subtasks, // Set of (task_idx, subtask_idx) for attackers
        const DagParser::TaskSet& taskset, // Full taskset for context
        int num_simulation_runs          // Number of simulations this estimate is based on
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
