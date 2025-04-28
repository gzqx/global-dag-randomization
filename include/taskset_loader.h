#ifndef TASKSET_LOADER_H
#define TASKSET_LOADER_H

#include "taskset.h"
#include <string>

namespace DagParser {

class TaskSetLoader {
public:
    // Loads all .dot files from the specified directory into the TaskSet object.
    // Returns true on success (even if no .dot files are found), false on directory error.
    bool load(const std::string& directory_path, TaskSet& taskset);
};

} // namespace DagParser

#endif // TASKSET_LOADER_H
