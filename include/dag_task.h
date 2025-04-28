#ifndef DAG_TASK_H
#define DAG_TASK_H

#include "sub_task.h"
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <limits> // For numeric_limits

namespace DagParser {

class DAGTask {
public:
    double period = 0.0;
    double deadline = 0.0;
    std::string source_file_path; // Store where it was loaded from

    std::vector<SubTask> nodes; // Stores all subtasks (nodes) of this DAG
    std::map<int, int> dot_id_to_node_index; // Maps DOT ID to vector index

    // --- New Members ---
    double volume = -1.0; // Cache calculated volume (-1 indicates not calculated)
    double critical_path_length = -1.0; // Cache calculated length (-1 indicates not calculated)
    int max_core_id_found=-1;

    // --- New Methods ---
    // Calculates the sum of WCETs of all nodes. Caches the result.
    double get_volume();
    // Calculates the length of the critical path (longest path by WCET sum). Caches the result.
    double get_critical_path_length();
    // --- New Getter ---
    // Returns the minimum number of cores implied (max_core_id + 1)
    // Returns 0 if no core IDs were found (max_core_id_found remains -1)
    // Returns 1 if max_core_id_found is 0.
    int get_required_cores() const;


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

};

} // namespace DagParser

#endif // DAG_TASK_H
