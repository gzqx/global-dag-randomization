#include "dot_parser.h"
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream> // For potential debug/error messages
#include <algorithm> // For std::find_if, std::remove_if
#include <cctype> // For isspace

namespace DagParser {

// Helper to trim leading/trailing whitespace
std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
    auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
    return (start < end ? std::string(start, end) : std::string());
}

// Helper to split string by delimiter, trimming results
std::vector<std::string> split_and_trim(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    return tokens;
}


// --- DotParser Implementation ---

bool DotParser::parse(const std::string& file_path, DAGTask& task) {
    std::ifstream dot_file(file_path);
    if (!dot_file.is_open()) {
        std::cerr << "Error: Could not open DOT file: " << file_path << std::endl;
        return false; // Indicate file opening failure
    }

    task.source_file_path = file_path;
    task.nodes.clear();
    task.dot_id_to_node_index.clear();
    task.max_core_id_found=-1;

    std::string line;
    int current_node_index = 0; // Index within the task.nodes vector
    std::vector<std::pair<int, int>> edges_to_add; // Store edges temporarily <from_dot_id, to_dot_id>

    bool task_info_found = false;

    while (std::getline(dot_file, line)) {
        line = trim(line);
        if (line.empty() || line.find("digraph Task {") != std::string::npos || line == "}") {
            continue; // Skip empty lines, graph start/end
        }

        try {
            ParsedLineInfo info = parse_line(line);

            switch (info.type) {
                case DotLineType::TASK_INFO:
                    if (task_info_found) {
                         std::cerr << "Warning: Multiple task info lines found in " << file_path << ". Using the last one." << std::endl;
                    }
                    task.period = info.task_period;
                    task.deadline = info.task_deadline;
                    task_info_found = true;
                    break;

                case DotLineType::NODE_DEF:
                    if (task.dot_id_to_node_index.count(info.node_dot_id)) {
                        throw std::runtime_error("Duplicate DOT node ID definition: " + std::to_string(info.node_dot_id));
                    }
                    task.nodes.emplace_back(); // Add a new SubTask
                    task.nodes.back().id = current_node_index; // Assign internal index
                    task.nodes.back().original_dot_id = info.node_dot_id;
                    task.nodes.back().wcet = info.node_wcet;
                    //task.nodes.back().core_id = info.node_core_id;
                    if (info.node_parsed_core_id >=0) {
                        task.max_core_id_found=std::max(task.max_core_id_found,info.node_parsed_core_id);
                    }

                    task.dot_id_to_node_index[info.node_dot_id] = current_node_index;
                    current_node_index++;
                    break;

                case DotLineType::EDGE_DEF:
                    // Store edges temporarily, resolve indices later
                    edges_to_add.push_back({info.edge_from_dot_id, info.edge_to_dot_id});
                    break;

                case DotLineType::OTHER:
                    // Ignore other lines for now, or add warnings if needed
                    // std::cerr << "Warning: Ignoring unrecognized line in " << file_path << ": " << line << std::endl;
                    break;
            }
        } catch (const std::exception& e) {
            dot_file.close();
            throw std::runtime_error("Error parsing line in " + file_path + ": '" + line + "' - " + e.what());
        }
    }

    dot_file.close();

    if (!task_info_found) {
         throw std::runtime_error("Task info node (i [shape=box...]) not found in " + file_path);
    }

    // Now resolve edges using the dot_id_to_node_index map
    for (const auto& edge_pair : edges_to_add) {
        int from_dot_id = edge_pair.first;
        int to_dot_id = edge_pair.second;

        if (!task.dot_id_to_node_index.count(from_dot_id)) {
            throw std::runtime_error("Edge source node DOT ID " + std::to_string(from_dot_id) + " not defined in " + file_path);
        }
        if (!task.dot_id_to_node_index.count(to_dot_id)) {
            throw std::runtime_error("Edge destination node DOT ID " + std::to_string(to_dot_id) + " not defined in " + file_path);
        }

        int from_index = task.dot_id_to_node_index[from_dot_id];
        int to_index = task.dot_id_to_node_index[to_dot_id];

        task.nodes[from_index].successors.push_back(to_index);
        task.nodes[to_index].predecessors.push_back(from_index);
    }

    return true;
}


DotParser::ParsedLineInfo DotParser::parse_line(const std::string& line) {
    ParsedLineInfo info;

    size_t arrow_pos = line.find("->");
    size_t bracket_open_pos = line.find('[');
    size_t bracket_close_pos = line.find(']');

    if (arrow_pos != std::string::npos && bracket_open_pos == std::string::npos) {
        // --- Edge Definition ---
        info.type = DotLineType::EDGE_DEF;
        std::string from_str = trim(line.substr(0, arrow_pos));
        std::string to_str = trim(line.substr(arrow_pos + 2, line.find(';') - (arrow_pos + 2)));

        try {
            info.edge_from_dot_id = std::stoi(from_str);
            info.edge_to_dot_id = std::stoi(to_str);
        } catch (const std::invalid_argument& ia) {
            throw std::runtime_error("Invalid integer in edge definition");
        } catch (const std::out_of_range& oor) {
            throw std::runtime_error("Integer out of range in edge definition");
        }

    } else if (bracket_open_pos != std::string::npos && bracket_close_pos != std::string::npos) {
        // --- Node Definition or Task Info ---
        std::string node_id_str = trim(line.substr(0, bracket_open_pos));
        std::string attributes = line.substr(bracket_open_pos + 1, bracket_close_pos - (bracket_open_pos + 1));

        if (node_id_str == "i") {
            // Task Info Node
            info.type = DotLineType::TASK_INFO;
            parse_node_attributes(attributes, info); // Extract the label first
        } else {
            // Regular Node Definition
            info.type = DotLineType::NODE_DEF;
            try {
                info.node_dot_id = std::stoi(node_id_str);
            } catch (const std::invalid_argument& ia) {
                throw std::runtime_error("Invalid integer for node DOT ID: " + node_id_str);
            } catch (const std::out_of_range& oor) {
                throw std::runtime_error("Node DOT ID out of range: " + node_id_str);
            }
            parse_node_attributes(attributes, info);
        }
    } else {
        info.type = DotLineType::OTHER; // Or potentially an error if strict parsing is needed
    }

    return info;
}

// Inside src/dot_parser.cpp

void DotParser::parse_node_attributes(const std::string& attributes, ParsedLineInfo& info) {
    // Robust parsing aware of quotes for attributes like label="..."
    std::string current_key;
    std::string current_value;
    bool in_quotes = false;
    bool reading_key = true;
    size_t current_pos = 0;

    info.node_parsed_core_id=-1;

    while (current_pos < attributes.length()) {
        char c = attributes[current_pos];

        if (reading_key) {
            if (c == '=') {
                reading_key = false; // Start reading value
                current_key = trim(current_key); // Trim the key found
            } else if (!std::isspace(c) || !current_key.empty()) { // Avoid leading spaces for key
                current_key += c;
            }
        } else { // Reading value
            if (!in_quotes) {
                // Outside quotes
                if (c == '"') {
                    in_quotes = true; // Start of quoted value
                    current_value = ""; // Reset value for quoted string
                } else if (c == ',') {
                    // End of unquoted value or end of attribute pair
                    current_value = trim(current_value);
                    // --- Process the completed key-value pair ---
                    // 
if (!current_key.empty()) {
                         if (current_key == "label") {
                             if (info.type == DotLineType::TASK_INFO) {
                                 parse_task_info_label(current_value, info);
                             } else if (info.type == DotLineType::NODE_DEF) {
                                 // --- Modified Label Parsing ---
                                 size_t open_paren = current_value.find('(');
                                 size_t close_paren = current_value.rfind(')');
                                 if (open_paren == std::string::npos || close_paren == std::string::npos || open_paren >= close_paren) {
                                      throw std::runtime_error("Malformed node label format: missing/misplaced parentheses in '" + current_value + "'");
                                 }
                                 std::string wcet_part = trim(current_value.substr(0, open_paren));
                                 std::string inner_part = trim(current_value.substr(open_paren + 1, close_paren - (open_paren + 1)));
                                 size_t comma_pos = inner_part.find(',');
                                 if (comma_pos == std::string::npos) { /* Handle error or assume no core ID */ }
                                 else {
                                     std::string core_part_full = trim(inner_part.substr(comma_pos + 1));
                                     size_t p_marker = core_part_full.find("p:");
                                     if (p_marker != std::string::npos) {
                                         std::string core_id_str = trim(core_part_full.substr(p_marker + 2));
                                         try {
                                             if (!core_id_str.empty()) {
                                                 info.node_parsed_core_id = std::stoi(core_id_str); // Store parsed ID
                                             }
                                         } catch (...) { /* Ignore conversion errors for core ID */ }
                                     }
                                 }
                                 // Parse WCET (must succeed)
                                 try {
                                     if (wcet_part.empty()) throw std::runtime_error("WCET part empty in label '" + current_value + "'");
                                     info.node_wcet = std::stod(wcet_part);
                                 } catch (const std::exception& e) {
                                     throw std::runtime_error("Invalid WCET '" + wcet_part + "' in label '" + current_value + "': " + e.what());
                                 }
                                 // --- End Modified Label Parsing ---
                             }
                         } // else if (current_key == "shape") { /* Handle shape */ }
                    }
                    // --- Reset for next pair ---
                    current_key = "";
                    current_value = "";
                    reading_key = true;

                } else if (!std::isspace(c) || !current_value.empty()) { // Avoid leading spaces for value
                    current_value += c; // Append to unquoted value
                }
            } else {
                // Inside quotes
                if (c == '"') {
                    in_quotes = false; // End of quoted value (value already accumulated)
                    // The comma or end of string will trigger processing
                } else {
                    current_value += c; // Append character within quotes
                }
            }
        }
        current_pos++;
    }

    // --- Process the last key-value pair after loop ends ---
    if (!reading_key && !current_key.empty()) {
        current_value = trim(current_value);
         if (current_key == "label") {
             if (info.type == DotLineType::TASK_INFO) {
                 parse_task_info_label(current_value, info);
             } else if (info.type == DotLineType::NODE_DEF) {
                 // --- Modified Label Parsing (repeated) ---
                 size_t open_paren = current_value.find('(');
                 size_t close_paren = current_value.rfind(')');
                 if (open_paren == std::string::npos || close_paren == std::string::npos || open_paren >= close_paren) { /* Handle error */ }

                 std::string wcet_part = trim(current_value.substr(0, open_paren));
                 std::string inner_part = trim(current_value.substr(open_paren + 1, close_paren - (open_paren + 1)));
                 size_t comma_pos = inner_part.find(',');
                 if (comma_pos != std::string::npos) {
                     std::string core_part_full = trim(inner_part.substr(comma_pos + 1));
                     size_t p_marker = core_part_full.find("p:");
                     if (p_marker != std::string::npos) {
                         std::string core_id_str = trim(core_part_full.substr(p_marker + 2));
                         try {
                             if (!core_id_str.empty()) {
                                 info.node_parsed_core_id = std::stoi(core_id_str); // Store parsed ID
                             }
                         } catch (...) { /* Ignore conversion errors */ }
                     }
                 }
                 // Parse WCET (must succeed)
                 try {
                     if (wcet_part.empty()) throw std::runtime_error("WCET part empty in label '" + current_value + "'");
                     info.node_wcet = std::stod(wcet_part);
                 } catch (const std::exception& e) {
                     throw std::runtime_error("Invalid WCET '" + wcet_part + "' in label '" + current_value + "': " + e.what());
                 }// --- End SIMPLIFIED Label Parsing ---
             }
         } // else if (current_key == "shape") { /* Handle shape */ }
    } else if (!current_key.empty() && reading_key) {
         // Key found but no value followed (malformed)
         throw std::runtime_error("Malformed attribute: Key '" + current_key + "' found without value at end of attributes string.");
    }

    if (in_quotes) {
        // Unterminated quote
        throw std::runtime_error("Malformed attribute: Unterminated quote at end of attributes string.");
    }
}



void DotParser::parse_task_info_label(const std::string& label, ParsedLineInfo& info) {
    // Parse "D=deadline T=period"
    std::stringstream ss(label);
    std::string segment;
    std::vector<std::string> parts;

    while (ss >> segment) {
        parts.push_back(segment);
    }

    if (parts.size() != 2) {
        throw std::runtime_error("Malformed task info label: " + label);
    }

    try {
        size_t d_eq = parts[0].find("D=");
        size_t t_eq = parts[1].find("T=");

        if (d_eq != 0 || t_eq != 0) {
             throw std::runtime_error("Malformed task info label parts: " + label);
        }

        info.task_deadline = std::stod(parts[0].substr(2));
        info.task_period = std::stod(parts[1].substr(2));

    } catch (const std::exception& e) { // Catches invalid_argument, out_of_range
        throw std::runtime_error("Error parsing task info label values '" + label + "': " + e.what());
    }
}


} // namespace DagParser
