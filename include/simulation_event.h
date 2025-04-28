#ifndef SIMULATION_EVENT_H
#define SIMULATION_EVENT_H

#include <string>

namespace DagSim { // Using a new namespace for simulation parts

enum class EventType {
    START,
    FINISH // No PREEMPT/RESUME needed for non-preemptive
};

struct SimulationEvent {
    double timestamp = 0.0;
    EventType type;
    int subtask_id = -1; // The internal index (SubTask::id)
    int core_id = -1;

    // For sorting events by time
    bool operator<(const SimulationEvent& other) const {
        return timestamp < other.timestamp;
    }
};

// Helper function to convert EventType to string for printing
inline std::string eventTypeToString(EventType type) {
    switch (type) {
        case EventType::START:  return "START";
        case EventType::FINISH: return "FINISH";
        default:                return "UNKNOWN";
    }
}

} // namespace DagSim

#endif // SIMULATION_EVENT_H
