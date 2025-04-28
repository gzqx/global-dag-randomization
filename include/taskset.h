#ifndef TASKSET_H
#define TASKSET_H

#include "dag_task.h"
#include <vector>
#include <string>
#include <iostream>

namespace DagParser {

class TaskSet {
public:
    std::vector<DAGTask> tasks;
    std::string source_directory; // Directory it was loaded from

    // Basic print for debugging
    void print() const {
         std::cout << "========================================\n"
                   << "TaskSet (Source Dir: " << source_directory << ")\n"
                   << "  Number of DAGs: " << tasks.size() << "\n"
                   << "----------------------------------------\n";
        for (size_t i = 0; i < tasks.size(); ++i) {
            std::cout << "--- DAG Index: " << i << " ---\n";
            tasks[i].print();
            std::cout << "----------------------------------------\n";
        }
         std::cout << "========================================\n";
    }
};

} // namespace DagParser

#endif // TASKSET_H
