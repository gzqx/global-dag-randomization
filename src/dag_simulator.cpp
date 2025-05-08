#include "dag_simulator.h"
#include "sub_task.h" // Need SubTaskState enum and members
#include <vector>
#include <queue>    // For event queue
#include <set>      // For ready queue (ordered by priority)
#include <map>      // For tracking core availability
#include <limits>   // For infinity
#include <stdexcept>
#include <algorithm> // For std::sort, std::find_if
#include <iostream>  // For debug prints

namespace DagSim {

// --- Internal Event Structure for Priority Queue ---
struct SimQueueEvent {
    double time;
    EventType type; // Using the same enum
    int subtask_id; // Internal index
    int core_id;    // Relevant for FINISH events

    // Order by time (earliest first), then FINISH before START
    bool operator>(const SimQueueEvent& other) const {
        if (time != other.time) {
            return time > other.time;
        }
        // If times are equal, FINISH events have higher priority (happen "before" START)
        return type > other.type;
    }
};

// --- Ready Queue Comparator (using absolute deadline) ---
// We need the DAG reference to access deadlines
struct ReadyComparator {
    const DagParser::DAGTask& dag_ref;
    ReadyComparator(const DagParser::DAGTask& dag) : dag_ref(dag) {}

    bool operator()(int task_idx1, int task_idx2) const {
        // Lower absolute deadline means higher priority
        // Assuming absolute deadline = dag deadline for single instance at t=0
        // If deadlines are equal, use index as tie-breaker (consistent ordering)
        if (dag_ref.deadline != dag_ref.deadline) { // Placeholder if tasks had different deadlines
             return dag_ref.deadline < dag_ref.deadline; // Example: Use DAG deadline
        }
        // Simple tie-breaking using index
        return task_idx1 < task_idx2;
    }
};


// --- DagSimulator Implementation ---

std::vector<SimulationEvent> DagSimulator::simulate_single_instance(DagParser::DAGTask& dag, int num_cores_to_use) {

    if (dag.nodes.empty()) {
        throw std::runtime_error("Cannot simulate an empty DAG.");
    }

    int num_cores = num_cores_to_use;
    if (num_cores <= 0) {
         // If max_core_id_found was -1, get_required_cores returns 0.
         // We need at least one core to run anything.
         std::cerr << "Warning: DAG implies 0 cores (max_core_id_found=" << dag.max_core_id_found
                   << "). Assuming 1 core for simulation." << std::endl;
         num_cores = 1;
         // Alternatively, throw an error:
         // throw std::runtime_error("Cannot simulate DAG: requires 0 cores.");
    }

    // --- Initialization ---
    double current_time = 0.0;
    std::vector<SimulationEvent> timeline; // The final output
    int finished_tasks_count = 0;

    // Reset state for all subtasks
    for (auto& node : dag.nodes) {
        node.reset_simulation_state();
    }

    // Event queue (min-heap based on time)
    std::priority_queue<SimQueueEvent, std::vector<SimQueueEvent>, std::greater<SimQueueEvent>> event_queue;

    // Ready queue (ordered by priority - using std::set for automatic sorting)
    // Stores indices of ready subtasks
    std::set<int, ReadyComparator> ready_queue{ReadyComparator(dag)};

    // Core availability tracking (core_id -> busy_until_time)
    std::map<int, double> core_busy_until;
    for (int i = 0; i < num_cores; ++i) {
        core_busy_until[i] = 0.0; // All cores free at time 0
    }

    // Add initially ready tasks (no predecessors) to the ready queue
    for (size_t i = 0; i < dag.nodes.size(); ++i) {
        if (dag.nodes[i].state == DagParser::SubTaskState::READY) {
            ready_queue.insert(i);
            // std::cout << "Time 0.0: Task " << i << " becomes READY (initial)" << std::endl;
        }
    }

    // --- Simulation Loop ---
    while (finished_tasks_count < dag.nodes.size()) {

        // --- 1. Try to schedule ready tasks onto idle cores ---
        bool scheduled_something = true;
        while (scheduled_something && !ready_queue.empty()) {
            scheduled_something = false;
            int best_ready_task_idx = -1;

            // Find highest priority ready task (first element in the set)
            best_ready_task_idx = *ready_queue.begin();

            // Find the earliest available core
            int best_core_id = -1;
            double earliest_core_available_time = std::numeric_limits<double>::infinity();

            for (const auto& pair : core_busy_until) {
                if (pair.second <= current_time) { // Core is idle *now*
                    best_core_id = pair.first;
                    earliest_core_available_time = current_time; // Can start immediately
                    break; // Found an immediately available core
                } else { // Core is busy, track when it becomes free
                    if (pair.second < earliest_core_available_time) {
                        earliest_core_available_time = pair.second;
                        // Keep track of which core it is, but prioritize immediately free ones
                    }
                }
            }
             // If no core is free *now*, find the one that frees up earliest
             if (best_core_id == -1) {
                  for (const auto& pair : core_busy_until) {
                       if (pair.second == earliest_core_available_time) {
                            best_core_id = pair.first;
                            break;
                       }
                  }
             }


            // If we found a ready task AND an available core (now or later)
            if (best_ready_task_idx != -1 && best_core_id != -1) {
                 // Can we start the task *now*?
                 if (earliest_core_available_time <= current_time) {
                     // Yes: Schedule it!
                     ready_queue.erase(ready_queue.begin()); // Remove from ready queue

                     DagParser::SubTask& task_to_run = dag.nodes[best_ready_task_idx];
                     task_to_run.state = DagParser::SubTaskState::RUNNING;
                     task_to_run.start_time = current_time;
                     task_to_run.assigned_core = best_core_id;
                     double finish_time = current_time + task_to_run.wcet; // Non-preemptive
                     task_to_run.finish_time = finish_time; // Store expected finish
                     task_to_run.remaining_wcet = 0.0; // Will finish in one go

                     // Update core busy time
                     core_busy_until[best_core_id] = finish_time;

                     // Add START event to timeline
                     timeline.push_back({current_time, EventType::START, best_ready_task_idx, best_core_id});
                     // Add FINISH event to event queue
                     event_queue.push({finish_time, EventType::FINISH, best_ready_task_idx, best_core_id});

                     // std::cout << "Time " << current_time << ": Task " << best_ready_task_idx << " START on Core " << best_core_id << " (Finish @ " << finish_time << ")" << std::endl;

                     scheduled_something = true; // We scheduled something, check again
                 } else {
                      // No core available *now*, highest priority task must wait.
                      // The next event will advance time.
                      scheduled_something = false;
                 }
            } else {
                 // Either no ready tasks or no cores available ever (shouldn't happen with finite tasks)
                 scheduled_something = false;
            }
        } // End scheduling loop for current time


        // --- 2. Advance time to the next event ---
        if (event_queue.empty() && ready_queue.empty() && finished_tasks_count < dag.nodes.size()) {
             // Should not happen in a valid DAG simulation unless there's a deadlock/logic error
             throw std::runtime_error("Simulation stuck: No events or ready tasks, but not all tasks finished.");
        }
         if (event_queue.empty() && !ready_queue.empty()) {
             // Ready tasks exist, but all cores are busy. Advance time to earliest core available time.
             double earliest_finish = std::numeric_limits<double>::infinity();
              for (const auto& pair : core_busy_until) {
                   earliest_finish = std::min(earliest_finish, pair.second);
              }
              if (earliest_finish <= current_time) {
                   // This case should have been handled by scheduling loop finding an idle core
                   throw std::runtime_error("Simulation logic error: Ready tasks exist, core should be free, but wasn't scheduled.");
              }
              current_time = earliest_finish;
              // std::cout << "Time advanced to " << current_time << " (earliest core available)" << std::endl;

         } else if (!event_queue.empty()) {
             // Advance time to the next event in the queue
             double next_event_time = event_queue.top().time;
             if (next_event_time < current_time) {
                  // Should not happen with a monotonic clock
                  throw std::runtime_error("Simulation time error: Next event time is in the past.");
             }
             current_time = next_event_time;
             // std::cout << "Time advanced to " << current_time << " (next event)" << std::endl;
         } else {
              // No ready tasks, no events -> simulation should be ending or stuck
              if (finished_tasks_count == dag.nodes.size()) break; // Normal exit
              else throw std::runtime_error("Simulation stuck: No events or ready tasks.");
         }


        // --- 3. Process events at the current time ---
        while (!event_queue.empty() && event_queue.top().time <= current_time) {
            SimQueueEvent current_event = event_queue.top();
            event_queue.pop();

            if (current_event.type == EventType::FINISH) {
                int finished_task_idx = current_event.subtask_id;
                DagParser::SubTask& finished_task = dag.nodes[finished_task_idx];

                // Ensure it wasn't already finished (sanity check)
                if (finished_task.state != DagParser::SubTaskState::RUNNING) {
                     std::cerr << "Warning: FINISH event for task " << finished_task_idx << " which is not RUNNING (state=" << (int)finished_task.state << "). Ignoring." << std::endl;
                     continue;
                }

                finished_task.state = DagParser::SubTaskState::FINISHED;
                // finish_time was already set when scheduled
                finished_tasks_count++;

                // Add FINISH event to timeline
                timeline.push_back({current_time, EventType::FINISH, finished_task_idx, finished_task.assigned_core});

                // std::cout << "Time " << current_time << ": Task " << finished_task_idx << " FINISH on Core " << finished_task.assigned_core << std::endl;


                // Check successors for readiness
                for (int successor_idx : finished_task.successors) {
                    DagParser::SubTask& successor_task = dag.nodes[successor_idx];
                    if (successor_task.state == DagParser::SubTaskState::NOT_READY) {
                        successor_task.predecessors_finished_count++;
                        if (successor_task.predecessors_finished_count == successor_task.predecessors.size()) {
                            successor_task.state = DagParser::SubTaskState::READY;
                            ready_queue.insert(successor_idx);
                             // std::cout << "Time " << current_time << ": Task " << successor_idx << " becomes READY" << std::endl;
                        }
                    }
                }
            }
            // Add handling for other event types if needed later (e.g., PREEMPT)
        } // End processing events at current time

    } // End simulation loop

    // Sort timeline just in case events at the same timestamp were added out of order
    std::sort(timeline.begin(), timeline.end());

    return timeline;
}


} // namespace DagSim
