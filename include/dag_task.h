#ifndef DAG_TASK_H
#define DAG_TASK_H

#include "sub_task.h"
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <limits>
#include <optional>
#include <set>     // For std::set
#include <random>  // For std::mt19937

namespace DagParser {

class DAGTask {
public:
    double period = 0.0;
    double deadline = 0.0;
    std::string source_file_path; // Store where it was loaded from

    std::vector<SubTask> nodes; // Stores all subtasks (nodes) of this DAG
    std::map<int, int> dot_id_to_node_index; // Maps DOT ID to vector index

    double volume = -1.0; // Cache calculated volume (-1 indicates not calculated)
    double critical_path_length = -1.0; // Cache calculated length (-1 indicates not calculated)
    int max_core_id_found=-1;

    // --- New Members for Algorithm 1 ---
    // Maps original node index 'v' to the WCET of its fake predecessor 'vf(v)'
    std::map<int, double> fake_task_wcets;
    bool fake_params_generated = false; // Flag if generation was successful
                                        //
    bool generate_fake_params(int m, std::mt19937& rng); // <-- ADDED rng parameter

    // Calculates the sum of WCETs of all nodes. Caches the result.
    double get_volume();
    // Calculates the length of the critical path (longest path by WCET sum). Caches the result.
    double get_critical_path_length();
    // Returns the minimum number of cores implied (max_core_id + 1)
    // Returns 0 if no core IDs were found (max_core_id_found remains -1)
    // Returns 1 if max_core_id_found is 0.
    int get_required_cores() const;

    // --- New Method for Algorithm 1 ---
    // Implements Algorithm 1 to generate WCETs for Step 1 fake tasks.
    // Returns true on success, false on failure (e.g., negative budget).
    // Stores results in this->fake_task_wcets.
    bool generate_fake_params(int m); // m = number of cores

        // Creates and returns a new DAGTask representing the graph augmented
    // with the Step 1 fake tasks (vf). Requires generate_fake_params
    // to have been called successfully first.
    // Throws std::runtime_error if fake params not generated.
    DAGTask create_augmented_graph_step1() const;

    // --- New Methods for Marking Vulnerable/Attacker Subtasks ---
    // Marks a fraction of original subtasks randomly.
    // num_vulnerable: how many original subtasks to mark as vulnerable.
    // num_attacker: how many original subtasks to mark as attacker-controlled.
    // rng: random number generator.
    // Note: A subtask can be both vulnerable and attacker-controlled if selected by both.
    void mark_subtasks_randomly(int num_vulnerable, int num_attacker, std::mt19937& rng);

    // Marks subtasks based on their original DOT IDs.
    // vulnerable_dot_ids: Set of original DOT IDs to mark as vulnerable.
    // attacker_dot_ids: Set of original DOT IDs to mark as attacker-controlled.
    void mark_subtasks_by_id(const std::set<int>& vulnerable_dot_ids,
                             const std::set<int>& attacker_dot_ids);

    // Clears all vulnerable/attacker markings and resets threat parameters on subtasks.
    void clear_threat_markings();

    // Basic print for debugging
    void print() const {
        std::cout << "DAG Task (Source: " << source_file_path << ")\n"
            << "  Period: " << period << ", Deadline: " << deadline << "\n";
        if (max_core_id_found >= 0) { // <-- ADD Check
            std::cout << "  Max Core ID Found (p): " << max_core_id_found << "\n"; // <-- ADD Print
            std::cout << "  Implied Min Cores: " << get_required_cores() << "\n"; // <-- ADD Print
        } else {
            std::cout << "  Max Core ID Found (p): Not specified in DOT\n"; // <-- ADD Print
        }
        if (volume >= 0.0) {
            std::cout << "  Volume: " << volume << "\n";
        }
        if (critical_path_length >= 0.0) {
            std::cout << "  Critical Path Length: " << critical_path_length << "\n";
        }
        std::cout << "  Nodes (" << nodes.size() << "):\n";
        for (const auto& node : nodes) {
            node.print(); // SubTask print was updated
        }
        // std::cout << "  DOT ID to Index Map:\n"; // Optional: Keep for debugging if needed
        // for(const auto& pair : dot_id_to_node_index) {
        //     std::cout << "    DOT ID " << pair.first << " -> Index " << pair.second << "\n";
        // }
    }

private:
    // --- Helper for critical path ---
    // Performs topological sort (if needed) and calculates path lengths.
    void calculate_longest_paths(std::vector<double>& longest_path_to_node);
    // Helper to get node indices sorted topologically
    std::vector<int> get_topological_order();

    // --- Helpers for Algorithm 1 ---
    // Calculates len(Ĝ_i) based on current fake_task_wcets
    double calculate_augmented_critical_path_length(
        const std::map<int, double>& current_fake_wcets,
        std::vector<int>& critical_path_nodes // Output: nodes on the critical path
    );
    // Calculates len_o: sum of original node WCETs on the given critical path
    double calculate_original_wcet_on_path(const std::vector<int>& path_nodes);
    // Placeholder for random distribution
    void distribute_randomly(double total_budget, std::map<int, double>& distribution_map, std::mt19937& rng);
};

} // namespace DagParser

#endif // DAG_TASK_H
