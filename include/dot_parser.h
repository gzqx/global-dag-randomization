#ifndef DOT_PARSER_H
#define DOT_PARSER_H

#include "dag_task.h"
#include <string>

namespace DagParser {

class DotParser {
public:
    // Parses a single DOT file and populates the given DAGTask object.
    // Returns true on success, false on failure.
    // Throws std::runtime_error on critical parsing errors.
    bool parse(const std::string& file_path, DAGTask& task);

private:
    // Helper enum and struct for internal line parsing state
    enum class DotLineType { TASK_INFO, NODE_DEF, EDGE_DEF, OTHER };
    struct ParsedLineInfo {
        DotLineType type = DotLineType::OTHER;
        // Task Info
        double task_period = 0.0;
        double task_deadline = 0.0;
        // Node Def
        int node_dot_id = -1;
        double node_wcet = 0.0;
        int node_parsed_core_id = -1; // <-- MODIFIED: Store parsed core ID temporarily (-1 if not found)
        // Edge Def
        int edge_from_dot_id = -1;
        int edge_to_dot_id = -1;
    };

    // Internal helper to parse a single line
    ParsedLineInfo parse_line(const std::string& line);
    // Helper to parse attributes within brackets [...]
    void parse_node_attributes(const std::string& attributes, ParsedLineInfo& info);
     // Helper to parse the task info label "D=... T=..."
    void parse_task_info_label(const std::string& label, ParsedLineInfo& info);
};

} // namespace DagParser

#endif // DOT_PARSER_H
