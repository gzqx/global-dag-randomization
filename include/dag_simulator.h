#ifndef DAG_SIMULATOR_H
#define DAG_SIMULATOR_H

#include "dag_task.h" // Needs access to the parsed DAG structure
#include "simulation_event.h"
#include <vector>
#include <string>

namespace DagSim {

class DagSimulator {
public:
    // Simulates a single instance of the given DAG arriving at time 0.
    // Assumes G-EDF non-preemptive scheduling.
    // Returns a timeline of events.
    // Throws std::runtime_error if DAG has no nodes or requires 0 cores.
    std::vector<SimulationEvent> simulate_single_instance(
            DagParser::DAGTask& dag,
            int num_cores_to_use
            );

private:
    // Helper function to find the highest priority (earliest deadline) ready task
    int find_highest_priority_ready_task(const DagParser::DAGTask& dag);
};

} // namespace DagSim

#endif // DAG_SIMULATOR_H
