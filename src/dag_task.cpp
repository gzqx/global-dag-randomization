#include "dag_task.h"
#include <numeric>   // For std::accumulate
#include <vector>
#include <map>
#include <algorithm> // For std::max, std::reverse
#include <stdexcept> // For runtime_error

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


} // namespace DagParser
