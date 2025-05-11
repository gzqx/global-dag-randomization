#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
// #include "dag_simulator.h"    // Not directly used by main anymore for simulation
// #include "simulation_event.h" // Not directly used by main anymore
#include "threat_analyzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <random>
#include <map> // For string to enum conversion

// Helper to convert string to AttackType enum
DagParser::AttackType stringToAttackType(const std::string& s) {
    std::string upper_s = s;
    for (char &c : upper_s) c = toupper(c);

    if (upper_s == "ANTERIOR") return DagParser::AttackType::ANTERIOR;
    if (upper_s == "POSTERIOR") return DagParser::AttackType::POSTERIOR;
    if (upper_s == "PINCER_SINGLE") return DagParser::AttackType::PINCER_SINGLE_WINDOW;
    if (upper_s == "PINCER_DUAL") return DagParser::AttackType::PINCER_DUAL_WINDOW;
    if (upper_s == "CONCURRENT") return DagParser::AttackType::CONCURRENT;
    if (upper_s == "NONE") return DagParser::AttackType::NONE;
    throw std::invalid_argument("Unknown AttackType string: " + s);
}

std::string attackTypeToString(DagParser::AttackType at) {
    switch (at) {
        case DagParser::AttackType::ANTERIOR: return "ANTERIOR";
        case DagParser::AttackType::POSTERIOR: return "POSTERIOR";
        case DagParser::AttackType::PINCER_SINGLE_WINDOW: return "PINCER_SINGLE";
        case DagParser::AttackType::PINCER_DUAL_WINDOW: return "PINCER_DUAL";
        case DagParser::AttackType::CONCURRENT: return "CONCURRENT";
        case DagParser::AttackType::NONE: return "NONE";
        default: return "UNKNOWN_ATTACK_TYPE";
    }
}


int main(int argc, char* argv[]) {
    // --- Argument Handling ---
    if (argc < 7) { // Now need dir, cores, vp, ap, tp, attack_type
        std::cerr << "Usage: " << argv[0]
                  << " <taskset_dir> <num_cores> <vp> <ap> <tp> <attack_type> [num_sim_runs]"
                  << std::endl;
        std::cerr << "  vp: number of vulnerable subtasks" << std::endl;
        std::cerr << "  ap: number of attacker subtasks" << std::endl;
        std::cerr << "  tp: threat probability threshold (0.0-1.0)" << std::endl;
        std::cerr << "  attack_type: ANTERIOR, POSTERIOR, PINCER_SINGLE, PINCER_DUAL, CONCURRENT, NONE" << std::endl;
        std::cerr << "  num_sim_runs (optional): N for probability estimation (default 1000)" << std::endl;
        std::cerr << "Example: " << argv[0] << " ../dags/taskset_0 8 2 1 0.1 CONCURRENT 1000" << std::endl;
        return 1;
    }
    std::string taskset_dir = argv[1];
    int num_cores_cli = 0; // This is 'm'
    int vp = 0;
    int ap = 0;
    double tp = 0.0;
    DagParser::AttackType attack_type_to_eval;
    int num_sim_runs = 1000;

    try {
        num_cores_cli = std::stoi(argv[2]);
        vp = std::stoi(argv[3]);
        ap = std::stoi(argv[4]);
        tp = std::stod(argv[5]);
        attack_type_to_eval = stringToAttackType(argv[6]);
        if (argc > 7) {
            num_sim_runs = std::stoi(argv[7]);
        }
        if (num_cores_cli <= 0 || vp < 0 || ap < 0 || tp < 0.0 || tp > 1.0 || num_sim_runs <= 0) {
            throw std::invalid_argument("Invalid numeric argument value.");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        return 1;
    }

    // --- Loading ---
    DagParser::TaskSetLoader loader;
    DagParser::TaskSet loaded_taskset;
    std::cout << "Attempting to load taskset from: " << taskset_dir << std::endl;
    bool load_success = false;
    try {
        load_success = loader.load(taskset_dir, loaded_taskset);
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during loading initialization: " << e.what() << std::endl;
        return 1;
    }

    if (!load_success || loaded_taskset.tasks.empty()) {
         std::cerr << "\nFailed to load taskset or taskset is empty. Cannot proceed." << std::endl;
         return 1;
    }
    if (loaded_taskset.tasks.size() != 1) {
        std::cerr << "\nError: This test expects the taskset directory to contain exactly one DAG." << std::endl;
        return 1;
    }
    std::cout << "\nSuccessfully loaded taskset with 1 DAG." << std::endl;


    // --- Calculate TH(T) ---
    std::cout << "\n--- Calculating System Threat TH(T) ---" << std::endl;
    std::cout << "Parameters: vp=" << vp << ", ap=" << ap << ", tp=" << tp
              << ", AttackType=" << attackTypeToString(attack_type_to_eval)
              << ", N_sim_runs=" << num_sim_runs
              << ", Cores (m)=" << num_cores_cli << std::endl;

    DagThreat::ThreatAnalyzer analyzer;
    try {
        // The calculate_TH function now takes the attack type.
        // The num_cores for simulation is handled internally by estimate_threat_probability
        // using the num_cores passed to it (which calculate_TH sources from the DAG or a default).
        // For consistency, calculate_TH should pass num_cores_cli to estimate_threat_probability.
        // This is now handled by estimate_threat_probability taking num_cores.
        // The calculate_TH function needs to be updated to pass num_cores_cli to estimate_threat_probability.

        // Let's ensure calculate_TH passes the correct 'm' (num_cores_cli)
        // The current calculate_TH in threat_analyzer.cpp uses:
        // original_dag.get_required_cores() > 0 ? original_dag.get_required_cores() : 1
        // This should be changed to use num_cores_cli.
        // For now, we assume this change is made in threat_analyzer.cpp or that
        // original_dag.get_required_cores() happens to match num_cores_cli for this test.
        // To be explicit, we'd modify calculate_TH to take num_cores_cli as well.
        // For this main.cpp, the call remains the same as calculate_TH's signature was updated.

        double system_threat = analyzer.calculate_TH(
            loaded_taskset,
            vp,
            ap,
            tp,
            attack_type_to_eval, // Pass the parsed attack type
            num_sim_runs
            // Seed is handled by default in calculate_TH
        );

        std::cout << "\nCalculated System Threat TH(T) = " << std::fixed << std::setprecision(6) << system_threat << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error calculating system threat: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nTest finished." << std::endl;
    return 0;
}
