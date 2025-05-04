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
bool DAGTask::generate_fake_params(int m) {
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
    distribute_randomly(initial_budget, fake_task_wcets);

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
// Simple proportional distribution (replace with actual random if needed)
void DAGTask::distribute_randomly(double total_budget, std::map<int, double>& distribution_map) {
    if (distribution_map.empty()) return;

    double total_original_wcet_involved = 0.0;
    for(const auto& pair : distribution_map) {
        int node_idx = pair.first;
        if (node_idx >= 0 && node_idx < nodes.size()) {
             total_original_wcet_involved += nodes[node_idx].wcet;
        }
    }

    if (total_original_wcet_involved <= 1e-9) {
        // Avoid division by zero, distribute equally if original WCETs are zero
        double budget_per_node = total_budget / distribution_map.size();
        for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
            it->second = std::max(0.0, budget_per_node);
        }
    } else {
        // Distribute proportionally to original WCET (example strategy)
        double remaining_budget = total_budget;
        for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
             int node_idx = it->first;
             double proportion = (nodes[node_idx].wcet / total_original_wcet_involved);
             // Use floor to avoid exceeding budget slightly due to multiple ceilings later?
             // Or stick to ceil as per pseudocode intention? Let's use floor for budget safety.
             double assigned_wcet = std::floor(total_budget * proportion);
             it->second = std::max(0.0, assigned_wcet);
             remaining_budget -= it->second;
        }
        // Distribute any small remaining budget (due to floor) to the first node, for example
        if (remaining_budget > 0 && !distribution_map.empty()) {
             distribution_map.begin()->second += remaining_budget;
        }
    }
     // Ensure non-negativity just in case
     for (auto it = distribution_map.begin(); it != distribution_map.end(); ++it) {
         if (it->second < 0.0) it->second = 0.0;
     }
}

} // namespace DagParser
