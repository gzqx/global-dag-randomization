#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
#include "dag_simulator.h"
#include "simulation_event.h"
#include "threat_analyzer.h" // <-- Include threat analyzer
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>

int main(int argc, char* argv[]) {
    // --- Argument Handling ---
    if (argc < 6) { // Now need dir, cores, vp, ap, tp
        std::cerr << "Usage: " << argv[0]
                  << " <taskset_dir> <num_cores> <vp> <ap> <tp> [num_sim_runs]"
                  << std::endl;
        std::cerr << "  vp: number of vulnerable tasks" << std::endl;
        std::cerr << "  ap: number of attacker tasks" << std::endl;
        std::cerr << "  tp: threat probability threshold (0.0-1.0)" << std::endl;
        std::cerr << "  num_sim_runs (optional): N for probability estimation (default 1000)" << std::endl;
        std::cerr << "Example: " << argv[0] << " ../dags/taskset_0 8 2 1 0.1 1000" << std::endl;
        return 1;
    }
    std::string taskset_dir = argv[1];
    int num_cores = 0;
    int vp = 0;
    int ap = 0;
    double tp = 0.0;
    int num_sim_runs = 1000; // Default simulation runs for estimation

    try {
        num_cores = std::stoi(argv[2]);
        vp = std::stoi(argv[3]);
        ap = std::stoi(argv[4]);
        tp = std::stod(argv[5]);
        if (argc > 6) {
            num_sim_runs = std::stoi(argv[6]);
        }
        if (num_cores <= 0 || vp < 0 || ap < 0 || tp < 0.0 || tp > 1.0 || num_sim_runs <= 0) {
            throw std::invalid_argument("Invalid numeric argument value.");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        return 1;
    }

    // --- Loading ---
    DagParser::TaskSetLoader loader;
    DagParser::TaskSet loaded_taskset;
    // ... (load taskset, handle errors) ...
     std::cout << "Attempting to load taskset from: " << taskset_dir << std::endl;
    bool load_success = false;
    try {
        load_success = loader.load(taskset_dir, loaded_taskset);
    } catch (const std::exception& e) { /* ... */ return 1; }
    if (!load_success || loaded_taskset.tasks.empty()) { /* ... */ return 1; }
    std::cout << "\nSuccessfully loaded taskset." << std::endl;


    // --- Calculate TH(T) ---
    std::cout << "\n--- Calculating System Threat TH(T) ---" << std::endl;
    std::cout << "Parameters: vp=" << vp << ", ap=" << ap << ", tp=" << tp
              << ", N=" << num_sim_runs << std::endl;

    DagThreat::ThreatAnalyzer analyzer;
    try {
        double system_threat = analyzer.calculate_TH(
            loaded_taskset, vp, ap, tp, num_sim_runs
        );
        std::cout << "\nCalculated System Threat TH(T) = " << system_threat << std::endl;
        std::cout << "(Note: Based on PLACEHOLDER threat probability estimation)" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error calculating system threat: " << e.what() << std::endl;
        return 1;
    }

    // --- Simulation Section (Optional - Keep or Remove) ---
    // You might want to remove or comment out the single-DAG simulation
    // part now, as the focus shifts to threat analysis which implies
    // multi-task simulation (handled by the placeholder).
    /*
    std::cout << "\n--- Simulating First DAG (Example) ---" << std::endl;
    if (!loaded_taskset.tasks.empty()) {
        DagParser::DAGTask& original_dag = loaded_taskset.tasks[0];
        bool params_ok = original_dag.generate_fake_params(num_cores);
        if (params_ok) {
            DagParser::DAGTask augmented_dag = original_dag.create_augmented_graph_step1();
            DagSim::DagSimulator simulator;
            std::vector<DagSim::SimulationEvent> timeline = simulator.simulate_single_instance(augmented_dag, num_cores);
            // ... print timeline ...
        } else {
            std::cout << "Skipping simulation as fake params failed." << std::endl;
        }
    }
    */

    std::cout << "\nTest finished." << std::endl;
    return 0;
}
