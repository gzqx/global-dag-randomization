#include "taskset_loader.h"
#include "dot_parser.h"
#include <filesystem> // Requires C++17
#include <iostream>
#include <vector>
#include <string>
#include <algorithm> // For std::sort

namespace fs = std::filesystem;

namespace DagParser {

bool TaskSetLoader::load(const std::string& directory_path, TaskSet& taskset) {
    taskset.source_directory = directory_path;
    taskset.tasks.clear();

    if (!fs::is_directory(directory_path)) {
        std::cerr << "Error: Provided path is not a directory: " << directory_path << std::endl;
        return false;
    }

    DotParser parser;
    std::vector<std::string> dot_files;
    bool all_files_parsed_successfully = true; // <-- Add this flag

    // Collect all .dot files
    try {
        for (const auto& entry : fs::directory_iterator(directory_path)) {
            if (entry.is_regular_file() && entry.path().extension() == ".dot") {
                dot_files.push_back(entry.path().string());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error iterating directory " << directory_path << ": " << e.what() << std::endl;
        return false;
    }

    // Optional: Sort files alphabetically or numerically if order matters
    std::sort(dot_files.begin(), dot_files.end());

    if (dot_files.empty()) {
        std::cerr << "Warning: No .dot files found in directory: " << directory_path << std::endl;
        // Return true because the directory was processed, just empty
    }

    // Parse each file
    for (const auto& dot_file_path : dot_files) {
        DAGTask current_dag;
        try {
            if (parser.parse(dot_file_path, current_dag)) {
                taskset.tasks.push_back(std::move(current_dag)); // Move parsed task into the set
            } else {
                // Parser::parse returning false indicates file open error, already printed
                // Potentially stop loading or just skip this file
                std::cerr << "Skipping file due to open error: " << dot_file_path << std::endl;
                all_files_parsed_successfully = false; // <-- Mark failure
            }
        } catch (const std::exception& e) {
            // Parser::parse throwing indicates a parsing error within the file
            std::cerr << "Error processing file " << dot_file_path << ": " << e.what() << std::endl;
            all_files_parsed_successfully = false; // <-- Mark failure
            // Decide whether to stop loading entirely or just skip the problematic file
            // For robustness, let's skip this file and continue
            // return false; // Uncomment this to stop on first error
        }
    }

    return all_files_parsed_successfully; // <-- Return the flag
}

} // namespace DagParser
