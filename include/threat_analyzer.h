#ifndef THREAT_ANALYZER_H
#define THREAT_ANALYZER_H

#include "taskset.h"
#include "sub_task.h"
#include "simulation_event.h" // For SimulationEvent
#include <vector>
#include <set>
#include <string>
#include <utility> // For std::pair
#include <map>     // For returning multiple results

namespace DagSim { class DagSimulator; } // Forward declaration

namespace DagThreat {

struct ThreatAnalysisResult {
    double th_original_dag = 0.0;
    double th_augmented_dag = 0.0;
};

class ThreatAnalyzer {
public:
    ThreatAnalyzer() = default;

    // Calculates threat for both original and augmented DAGs.
    ThreatAnalysisResult calculate_comparative_TH(
        const DagParser::TaskSet& taskset, // Assumed to contain one DAG
        int vp,
        int ap,
        double tp,
        DagParser::AttackType attack_type_to_evaluate,
        int num_cores, // The 'm' for the system
        int num_simulation_runs_per_estimation,
        unsigned int seed = std::random_device{}()
    );
    std::map<int, double> calculate_task_distribution_entropy(
            DagParser::DAGTask& original_dag, // Non-const to allow fake param regeneration
            const std::set<int>& subtask_indices_to_analyze,
            int num_cores_m,
            int num_entropy_runs,
            unsigned int rng_seed = std::random_device{}()
            );


private:
    // Core estimation logic for a given DAG generation strategy (original or augmented)
    double _estimate_threat_for_dag_config(
        const DagParser::SubTask& vulnerable_subtask_ref, // From original DAG
        DagParser::AttackType attack_type_to_evaluate,
        const std::set<std::pair<int, int>>& attacker_subtask_identifiers, // Original {0, subtask_idx}
        DagParser::DAGTask& base_dag, // The original DAG, non-const for fake param regen
        bool use_augmentation,        // True to generate fake params and augment
        int num_cores,
        int num_simulation_runs,
        std::mt19937& rng,
        DagSim::DagSimulator& simulator // Pass simulator by reference
    );

    // Checks if a threat occurred in a single simulated timeline
    bool _check_threat_in_timeline(
        const std::vector<DagSim::SimulationEvent>& timeline,
        const DagParser::DAGTask& simulated_dag_structure, // Structure of the DAG that was simulated
        int vulnerable_subtask_original_dot_id, // To find the vulnerable subtask
        const DagParser::SubTask& vulnerable_subtask_params, // For Δs and Cα
        DagParser::AttackType attack_type_to_evaluate,
        const std::set<std::pair<int, int>>& attacker_subtask_identifiers, // Original {0, subtask_idx}
        const DagParser::DAGTask& original_dag_for_ids // To get attacker original_dot_ids
    );

    // --- Existing helpers ---
    double epsilon_threshold(double value, double threshold_tp);
    // select_random_task_indices and get_subtask_indices are now part of calculate_comparative_TH
    // static std::vector<std::pair<double, double>> calculate_vulnerable_window(...); // Keep this
public: // Make it public static or move to a utility if used elsewhere
    static std::vector<std::pair<double, double>> calculate_vulnerable_window(
        DagParser::AttackType attack_type,
        double subtask_sim_start_time,
        double subtask_sim_end_time,
        double delta_minus,
        double delta_plus
    );
};

} // namespace DagThreat
#endif // THREAT_ANALYZER_H
