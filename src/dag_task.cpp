#include "dag_task.h"
#include <numeric>
#include <vector>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <cmath>     // For std::ceil
#include <random>    // For random distribution
#include <iostream>  // For warnings/debug
namespace DagParser {

// --- get_volume Implementation ---
double DAGTask::get_volume() {
    // Return cached value if already calculated
    if (volume >= 0.0) {
        return volume;
    }

    // Calculate volume: sum of all node WCETs
    double calculated_volume = 0.0;
    for (const auto& node : nodes) {
        calculated_volume += node.wcet;
    }

    // Cache and return
    volume = calculated_volume;
    return volume;
}


// --- get_critical_path_length Implementation ---
double DAGTask::get_critical_path_length() {
    // Return cached value if already calculated
    if (critical_path_length >= 0.0) {
        return critical_path_length;
    }
    if (nodes.empty()) {
        critical_path_length = 0.0;
        return 0.0;
    }

    // Calculate longest path to each node using topological sort
    std::vector<double> longest_path_to_node(nodes.size(), 0.0);
    calculate_longest_paths(longest_path_to_node);

    // The critical path length is the maximum value in longest_path_to_node
    double max_len = 0.0;
    for (double path_len : longest_path_to_node) {
        if (path_len > max_len) {
            max_len = path_len;
        }
    }

    // Cache and return
    critical_path_length = max_len;
    return critical_path_length;
}

// --- Private Helper: calculate_longest_paths ---
void DAGTask::calculate_longest_paths(std::vector<double>& longest_path_to_node) {
    if (nodes.empty()) return;

    std::vector<int> sorted_indices = get_topological_order();

    // Initialize longest path for all nodes
    longest_path_to_node.assign(nodes.size(), 0.0);

    // Iterate through nodes in topological order
    for (int node_index : sorted_indices) {
        double max_pred_path = 0.0;
        // Find the maximum path length among all predecessors
        for (int pred_index : nodes[node_index].predecessors) {
            // Ensure predecessor index is valid (should be if graph is valid)
             if (pred_index >= 0 && pred_index < longest_path_to_node.size()) {
                 max_pred_path = std::max(max_pred_path, longest_path_to_node[pred_index]);
             } else {
                  throw std::runtime_error("Invalid predecessor index encountered during longest path calculation.");
             }
        }
        // Longest path to current node = its WCET + max path length of predecessors
        longest_path_to_node[node_index] = nodes[node_index].wcet + max_pred_path;
    }
}


// --- Private Helper: get_topological_order ---
// Standard Kahn's algorithm for topological sort
std::vector<int> DAGTask::get_topological_order() {
    if (nodes.empty()) return {};

    std::vector<int> in_degree(nodes.size(), 0);
    std::vector<std::vector<int>> adj(nodes.size()); // Adjacency list for successors

    // Calculate in-degrees and build adjacency list
    for (size_t i = 0; i < nodes.size(); ++i) {
        in_degree[i] = nodes[i].predecessors.size();
        for (int successor_index : nodes[i].successors) {
             if (successor_index >= 0 && successor_index < nodes.size()) {
                 adj[i].push_back(successor_index);
             } else {
                 throw std::runtime_error("Invalid successor index found during topological sort setup.");
             }
        }
    }

    // Queue for nodes with in-degree 0
    std::vector<int> queue;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (in_degree[i] == 0) {
            queue.push_back(i);
        }
    }

    std::vector<int> result_order;
    int head = 0; // Use index instead of actual queue for simplicity here

    while(head < queue.size()){
        int u = queue[head++]; // Dequeue
        result_order.push_back(u);

        // For each neighbor v of u
        for (int v : adj[u]) {
            in_degree[v]--;
            if (in_degree[v] == 0) {
                queue.push_back(v); // Enqueue
            }
        }
    }

    // Check for cycles
    if (result_order.size() != nodes.size()) {
        throw std::runtime_error("Cycle detected in the DAG, cannot perform topological sort.");
    }

    return result_order;
}

int DAGTask::get_required_cores() const {
    if (max_core_id_found < 0) {
        return 0; // Indicate that no core info was available
    } else {
        return max_core_id_found + 1; // Number of cores = max_id + 1 (assuming 0-based)
    }
}

// --- New Method: generate_fake_params (Algorithm 1) ---
bool DAGTask::generate_fake_params(int m, std::mt19937& rng) {
    fake_params_generated = false; // Reset flag
    fake_task_wcets.clear();

    if (nodes.empty()) {
        std::cerr << "Warning: Cannot generate fake params for empty DAG." << std::endl;
        return true; // Or false? Arguably successful as there's nothing to do.
    }
    if (m <= 0) {
         throw std::runtime_error("Number of cores (m) must be positive.");
    }

    // Ensure original properties are calculated
    double vol_Gi = get_volume();
    double len_Gi = get_critical_path_length(); // len(G_i)

    // Line 6: Calculate initial budget
    double initial_budget = m * deadline - vol_Gi - (m - 1.0) * len_Gi;

    // Line 7-8: Check budget
    if (initial_budget < 0.0) {
        std::cerr << "Warning: Initial budget for fake tasks is negative ("
                  << initial_budget << "). Cannot generate randomness." << std::endl;
        return false; // Failure
    }

    // Identify nodes needing fake predecessors (all non-source nodes)
    std::vector<int> nodes_needing_fake;
    for(size_t i = 0; i < nodes.size(); ++i) {
        if (!nodes[i].predecessors.empty()) {
            nodes_needing_fake.push_back(i);
            fake_task_wcets[i] = 0.0; // Initialize map entry
        }
    }
     if (nodes_needing_fake.empty()) {
         // Only a source node exists, no fake tasks needed. Condition holds trivially if budget >= 0.
         fake_params_generated = true;
         return true;
     }


    // Line 9: Initial Distribution
    distribute_randomly(initial_budget, fake_task_wcets, rng);

    // Line 10-21: Repeat loop
    double rhs_budget = m * deadline - vol_Gi; // Constant part of RHS
    double lhs_value = 0.0;
    int max_iterations = nodes.size() * nodes.size(); // Heuristic limit to prevent infinite loops
    int iterations = 0;

    do {
        if (iterations++ > max_iterations) {
             throw std::runtime_error("Max iterations reached in generate_fake_params, potential convergence issue.");
        }

        // Calculate current augmented graph properties
        std::vector<int> current_critical_path_nodes; // Stores original node indices on CP
        double len_augmented_Gi = calculate_augmented_critical_path_length(
            fake_task_wcets, current_critical_path_nodes
        );

        // Line 11: Calculate len_o (sum of original WCETs on the critical path)
        double len_o = calculate_original_wcet_on_path(current_critical_path_nodes);

        // Line 12: Calculate C_fake_total
        double c_fake_total = 0.0;
        for (const auto& pair : fake_task_wcets) {
            c_fake_total += pair.second;
        }

        // Line 13: Calculate LHS_value
        lhs_value = (m - 1.0) * len_augmented_Gi + c_fake_total;

        // Check termination condition (Line 21)
        if (lhs_value <= rhs_budget) {
            break; // Success
        }

        // Line 15: Calculate sigma_estimate
        double numerator = rhs_budget - (m - 1.0) * len_o;
        double denominator = (m - 1.0) * (len_augmented_Gi - len_o) + c_fake_total;

        // Prevent division by zero or near-zero, or scaling up
        if (denominator <= 1e-9) {
             // This might happen if all fake tasks are zero and len_augmented == len_o,
             // but LHS > RHS. Indicates an issue or impossible target.
             std::cerr << "Warning: Denominator near zero in sigma calculation. LHS=" << lhs_value
                       << ", RHS_budget=" << rhs_budget << ", Denom=" << denominator << std::endl;
             // If LHS > RHS and denom is zero, we can't scale down. Fail.
             if (lhs_value > rhs_budget) return false;
             // Otherwise, maybe it's okay? Break cautiously.
             break;
        }

        double sigma_estimate = numerator / denominator;

        // Ensure scaling factor is <= 1 (we only scale down)
        if (sigma_estimate > 1.0) {
             // This implies RHS_budget > LHS_value already, loop should have terminated.
             // Or it could happen if len_o > len_augmented_Gi, which shouldn't occur.
             std::cerr << "Warning: sigma_estimate > 1 (" << sigma_estimate
                       << "). LHS=" << lhs_value << ", RHS_budget=" << rhs_budget
                       << ". Clamping to 1.0." << std::endl;
             sigma_estimate = 1.0; // Clamp, though this indicates a potential logic issue
        }
         if (sigma_estimate < 0.0) {
              // Numerator is negative, meaning even with zero fake tasks, the original
              // tasks on the critical path exceed the budget.
              std::cerr << "Warning: sigma_estimate < 0 (" << sigma_estimate
                        << "). Cannot satisfy budget." << std::endl;
              return false; // Cannot satisfy
         }


        // Line 16-20: Apply scaling
        std::map<int, double> next_fake_wcets; // Use a temporary map for updates
        for (const auto& pair : fake_task_wcets) {
             int node_idx = pair.first;
             double current_c_fake = pair.second;
             // Line 18: Calculate c_new using flooring
             double c_new = std::floor(sigma_estimate * current_c_fake);
             // Ensure non-negativity after ceiling (shouldn't be needed if sigma>=0)
             next_fake_wcets[node_idx] = std::max(0.0, c_new);
        }
        fake_task_wcets = next_fake_wcets; // Update the member map

    } while (true); // Condition checked inside loop

    fake_params_generated = true;
    return true; // Success
}


// --- Private Helper: calculate_augmented_critical_path_length ---
// Calculates len(Ĝ_i) where Ĝ_i includes Step 1 fake tasks vf(v)
double DAGTask::calculate_augmented_critical_path_length(
    const std::map<int, double>& current_fake_wcets,
    std::vector<int>& critical_path_nodes // Output: original node indices on CP
) {
    if (nodes.empty()) return 0.0;

    std::vector<int> sorted_indices = get_topological_order();
    std::vector<double> longest_path_to_node(nodes.size(), 0.0); // Longest path ending *at the original node v*
    std::vector<int> predecessor_on_cp(nodes.size(), -1); // Track path for output

    for (int node_index : sorted_indices) {
        double max_pred_path = 0.0;
        int best_pred_idx = -1;

        // Find max path ending at any *original* predecessor u
        for (int pred_index : nodes[node_index].predecessors) {
             if (pred_index >= 0 && pred_index < longest_path_to_node.size()) {
                 if (longest_path_to_node[pred_index] > max_pred_path) {
                     max_pred_path = longest_path_to_node[pred_index];
                     best_pred_idx = pred_index;
                 }
             } else {
                 throw std::runtime_error("Invalid predecessor index in augmented path calc.");
             }
        }

        // Cost to reach node 'v' = max_path_to_pred(u) + c(vf(v)) + c(v)
        double fake_wcet = 0.0;
        if (current_fake_wcets.count(node_index)) {
            fake_wcet = current_fake_wcets.at(node_index);
        } // else it's the source node, fake_wcet is 0

        longest_path_to_node[node_index] = max_pred_path + fake_wcet + nodes[node_index].wcet;
        predecessor_on_cp[node_index] = best_pred_idx; // Store which predecessor led to max path
    }

    // Find the overall maximum path length (ending at any sink node)
    double max_len = 0.0;
    int sink_node_idx = -1;
    for (size_t i = 0; i < nodes.size(); ++i) {
         // Consider only sink nodes of the original graph for the final length
         if (nodes[i].successors.empty()) {
             if (longest_path_to_node[i] > max_len) {
                 max_len = longest_path_to_node[i];
                 sink_node_idx = i;
             }
         }
         // Alternative: just take the max over all nodes
         // if (longest_path_to_node[i] > max_len) {
         //     max_len = longest_path_to_node[i];
         //     sink_node_idx = i;
         // }
    }

    // Reconstruct the critical path (original nodes only)
    critical_path_nodes.clear();
    int current_cp_node = sink_node_idx;
    while (current_cp_node != -1) {
        critical_path_nodes.push_back(current_cp_node);
        if (current_cp_node < predecessor_on_cp.size()) {
             current_cp_node = predecessor_on_cp[current_cp_node];
        } else {
             break; // Should not happen
        }
    }
    std::reverse(critical_path_nodes.begin(), critical_path_nodes.end());


    return max_len;
}

// --- Private Helper: calculate_original_wcet_on_path ---
double DAGTask::calculate_original_wcet_on_path(const std::vector<int>& path_nodes) {
    double sum = 0.0;
    for (int node_index : path_nodes) {
        if (node_index >= 0 && node_index < nodes.size()) {
            sum += nodes[node_index].wcet;
        } else {
             throw std::runtime_error("Invalid node index in critical path for len_o calculation.");
        }
    }
    return sum;
}


// --- Private Helper: distribute_randomly ---
void DAGTask::distribute_randomly(double total_budget, std::map<int, double>& distribution_map, std::mt19937& rng) {
    if (distribution_map.empty()) {
        return; // Nothing to distribute
    }

    // Ensure all map entries exist, initialize to 0.0 (will be overwritten)
    // This also allows us to easily get the count 'n'.
    for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
         it->second = 0.0;
    }

    size_t n = distribution_map.size();
    long long budget_to_distribute = std::floor(total_budget);

    // Handle non-positive budget
    if (budget_to_distribute <= 0) {
        // Set all to 0 (already done implicitly, but good to be explicit)
        for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
             it->second = 0.0;
        }
        return;
    }

    // --- Use UUniFast-like approach for dividing the budget ---
    //std::random_device rd;
    //std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_real_distribution<> dis(0.0, 1.0);

    std::vector<double> random_points(n - 1);
    for (size_t i = 0; i < n - 1; ++i) {
        random_points[i] = dis(rng); // Generate n-1 random points
    }
    std::sort(random_points.begin(), random_points.end()); // Sort them

    // Create n intervals based on sorted points
    std::vector<double> shares(n);
    double prev_point = 0.0;
    for (size_t i = 0; i < n - 1; ++i) {
        shares[i] = random_points[i] - prev_point;
        prev_point = random_points[i];
    }
    shares[n - 1] = 1.0 - prev_point; // Last share goes up to 1.0

    // --- Assign integer parts based on shares and distribute remainder ---
    long long total_assigned = 0;
    std::vector<int> node_indices; // Need indices to iterate consistently
    node_indices.reserve(n);
    for(const auto& pair : distribution_map) {
        node_indices.push_back(pair.first);
    }

    // Assign floored values
    for (size_t i = 0; i < n; ++i) {
        int node_idx = node_indices[i];
        long long assigned_wcet = std::floor(shares[i] * budget_to_distribute);
        distribution_map[node_idx] = static_cast<double>(assigned_wcet);
        total_assigned += assigned_wcet;
    }

    // Calculate remainder due to flooring
    long long remainder = budget_to_distribute - total_assigned;

    // Distribute remainder randomly
    if (remainder > 0) {
        // Create a shuffled list of indices to distribute remainder fairly
        std::vector<int> shuffled_indices = node_indices;
        std::shuffle(shuffled_indices.begin(), shuffled_indices.end(), rng);

        for (long long i = 0; i < remainder; ++i) {
            // Assign +1 to the first 'remainder' tasks in the shuffled list
            int node_idx_to_increment = shuffled_indices[i % n]; // Use modulo just in case remainder > n (shouldn't happen with floor)
            distribution_map[node_idx_to_increment] += 1.0;
        }
    }

    // Final check for non-negativity (should be guaranteed by logic)
    for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
        if (it->second < 0.0) {
             // This should ideally not happen with the floor approach
             std::cerr << "Warning: Negative WCET assigned in distribute_randomly. Setting to 0." << std::endl;
             it->second = 0.0;
        }
         // Ensure integer value is stored, although map is double
         it->second = std::floor(it->second);
    }

}

DAGTask DAGTask::create_augmented_graph_step1() const {
    if (!fake_params_generated) {
        throw std::runtime_error("Cannot create augmented graph: fake parameters have not been successfully generated.");
    }
    if (nodes.empty()) {
        return DAGTask(); // Return empty task if original is empty
    }

    DAGTask augmented_dag;
    augmented_dag.period = this->period;
    augmented_dag.deadline = this->deadline;
    augmented_dag.max_core_id_found = this->max_core_id_found; // Inherit core info if needed later
    augmented_dag.source_file_path = this->source_file_path + " (augmented)";

    // Mappings:
    // original_idx -> augmented_idx (for original nodes)
    std::map<int, int> orig_to_aug_idx;
    // original_idx -> augmented_idx (for fake nodes vf(original_idx))
    std::map<int, int> orig_to_fake_idx;

    int aug_idx_counter = 0;

    // Pass 1: Create all nodes
    for (size_t i = 0; i < this->nodes.size(); ++i) {
        const SubTask& original_node_ref = this->nodes[i];

        if (this->fake_task_wcets.count(i)) { // Node 'i' has a fake predecessor
            augmented_dag.nodes.emplace_back();
            SubTask& fake_node = augmented_dag.nodes.back();
            fake_node.id = aug_idx_counter;
            // Mark fake nodes with a distinct original_dot_id pattern, e.g., negative
            // Ensure it's different from any valid original_dot_id.
            // Adding 1 before negating avoids -0 if original_dot_id was 0.
            fake_node.original_dot_id = -(original_node_ref.original_dot_id + 1000000); // Large offset to avoid collision
            fake_node.wcet = this->fake_task_wcets.at(i);
            // is_vulnerable, is_attacker_controlled, deltas, C_alpha are false/0 for fake tasks
            orig_to_fake_idx[i] = aug_idx_counter;
            aug_idx_counter++;
        }

        // Add original node (copying all its properties, including threat markings and params)
        augmented_dag.nodes.push_back(original_node_ref);
        SubTask& aug_original_node = augmented_dag.nodes.back();
        aug_original_node.id = aug_idx_counter; // New sequential ID in augmented graph
        // original_dot_id is already copied from original_node_ref
        // Threat markings (is_vulnerable, etc.) and params (deltas, C_alpha) are copied.
        aug_original_node.predecessors.clear(); // Will be rewired
        aug_original_node.successors.clear();   // Will be rewired
        // Simulation state will be reset later for all nodes in augmented_dag

        orig_to_aug_idx[i] = aug_idx_counter;
        aug_idx_counter++;
    }

    // Pass 2: Wire up predecessors and successors (logic mostly unchanged)
    // ... (ensure this logic correctly uses orig_to_aug_idx and orig_to_fake_idx
    //      to connect nodes within augmented_dag.nodes) ...
    for (size_t i = 0; i < this->nodes.size(); ++i) {
        const SubTask& original_node_ref = this->nodes[i];
        int current_aug_orig_node_idx = orig_to_aug_idx.at(i);

        if (orig_to_fake_idx.count(i)) { // Node 'i' has a fake predecessor vf(i)
            int current_aug_fake_node_idx = orig_to_fake_idx.at(i);

            // 1. Link vf(i) -> v (original node i in augmented graph)
            augmented_dag.nodes[current_aug_fake_node_idx].successors.push_back(current_aug_orig_node_idx);
            augmented_dag.nodes[current_aug_orig_node_idx].predecessors.push_back(current_aug_fake_node_idx);

            // 2. Link original predecessors u -> vf(i)
            for (int orig_pred_idx_of_i : original_node_ref.predecessors) {
                int aug_idx_of_orig_pred_u = orig_to_aug_idx.at(orig_pred_idx_of_i);
                augmented_dag.nodes[aug_idx_of_orig_pred_u].successors.push_back(current_aug_fake_node_idx);
                augmented_dag.nodes[current_aug_fake_node_idx].predecessors.push_back(aug_idx_of_orig_pred_u);
            }
        } else { // Node 'i' is an original source node
            for (int orig_succ_idx_of_i : original_node_ref.successors) {
                int aug_target_node_idx; // This will be the node that 'i' points to in augmented graph
                if (orig_to_fake_idx.count(orig_succ_idx_of_i)) {
                    // Successor 'orig_succ_idx_of_i' has a fake task, so 'i' points to that fake task
                    aug_target_node_idx = orig_to_fake_idx.at(orig_succ_idx_of_i);
                } else {
                    // Successor 'orig_succ_idx_of_i' is itself a source (or has no preds), so 'i' points to it directly
                    aug_target_node_idx = orig_to_aug_idx.at(orig_succ_idx_of_i);
                }
                augmented_dag.nodes[current_aug_orig_node_idx].successors.push_back(aug_target_node_idx);
                augmented_dag.nodes[aug_target_node_idx].predecessors.push_back(current_aug_orig_node_idx);
            }
        }
    }


    // Reset simulation state for all nodes in the newly created graph
    for(auto& node : augmented_dag.nodes) {
        node.reset_simulation_state();
    }

    return augmented_dag;
}

void DAGTask::clear_threat_markings() {
    for (auto& node : nodes) {
        node.reset_threat_params();
    }
}

void assign_threat_parameters(SubTask& node) {
    if (node.is_vulnerable) {
        node.delta_minus = std::max(1.0, std::floor(0.10 * node.wcet));
        node.delta_plus  = std::max(1.0, std::floor(0.10 * node.wcet));
        node.c_alpha_requirement = std::max(1.0, std::floor(0.05 * node.wcet));
        // For now, we don't differentiate C_alpha by attack type,
        // so primary_vulnerable_attack_type is not strictly needed yet.
    }
}

void DAGTask::mark_subtasks_randomly(int num_vulnerable, int num_attacker, std::mt19937& rng) {
    clear_threat_markings();

    if (nodes.empty()) return;
    if (num_vulnerable < 0 || num_attacker < 0) {
        throw std::invalid_argument("Number of vulnerable/attacker tasks cannot be negative.");
    }

    size_t total_original_nodes = nodes.size();
    // Clamp to max possible
    num_vulnerable = std::min(static_cast<int>(total_original_nodes), num_vulnerable);
    num_attacker   = std::min(static_cast<int>(total_original_nodes), num_attacker);


    std::vector<int> indices(total_original_nodes);
    std::iota(indices.begin(), indices.end(), 0);

    // Mark vulnerable tasks
    std::shuffle(indices.begin(), indices.end(), rng);
    for (int i = 0; i < num_vulnerable; ++i) {
        nodes[indices[i]].is_vulnerable = true;
        assign_threat_parameters(nodes[indices[i]]); // Assign Δ and Cα
    }

    // Mark attacker-controlled tasks
    std::shuffle(indices.begin(), indices.end(), rng); // Re-shuffle for independent selection
    for (int i = 0; i < num_attacker; ++i) {
        nodes[indices[i]].is_attacker_controlled = true;
    }
}
void DAGTask::mark_subtasks_by_id(const std::set<int>& vulnerable_dot_ids,
                                  const std::set<int>& attacker_dot_ids) {
    clear_threat_markings();

    for (size_t i = 0; i < nodes.size(); ++i) {
        if (vulnerable_dot_ids.count(nodes[i].original_dot_id)) {
            nodes[i].is_vulnerable = true;
            assign_threat_parameters(nodes[i]); // Assign Δ and Cα
        }
        if (attacker_dot_ids.count(nodes[i].original_dot_id)) {
            nodes[i].is_attacker_controlled = true;
        }
    }
}

} // namespace DagParser
