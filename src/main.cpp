#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
#include "threat_analyzer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <random>
#include <numeric>
#include <cmath>
#include <map>
#include <omp.h> // For OpenMP

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
    if (upper_s == "ALL_RELEVANT") return static_cast<DagParser::AttackType>(-1); // Special value for ALL
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
    //disable cout to save IO overhead
    static std::ofstream null_stream("/dev/null");
    std::cout.rdbuf(null_stream.rdbuf());
    // --- Argument Handling ---
     const int MIN_REQUIRED_ARGS = 8; // Program name + 7 required args

    if (argc < MIN_REQUIRED_ARGS) {
        std::cerr << "Usage: " << argv[0]
                  << " <taskset_dir> <num_cores> <vp_count|-1> <ap_count|-1> <tp> <attack_type|ALL_RELEVANT> <num_macro_runs> [num_sim_runs_per_TH] [output_csv_file]"
                  << std::endl;
        std::cerr << "  vp_count: number of vulnerable subtasks, or -1 to auto-sweep" << std::endl;
        std::cerr << "  ap_count: number of attacker subtasks, or -1 to auto-sweep" << std::endl;
        std::cerr << "  tp: threat probability threshold (0.0-1.0)" << std::endl;
        std::cerr << "  attack_type: ANTERIOR, POSTERIOR, PINCER_SINGLE, PINCER_DUAL, CONCURRENT, NONE, ALL_RELEVANT" << std::endl;
        std::cerr << "  num_macro_runs: Number of times to repeat TH calculation with new random subtask selections" << std::endl;
        std::cerr << "  num_sim_runs_per_TH (optional): N for probability estimation (default 1000)" << std::endl;
        std::cerr << "  output_csv_file (optional): Path to CSV output file" << std::endl;
        std::cerr << "Example: " << argv[0] << " ../dags/taskset_0 8 -1 -1 0.1 CONCURRENT 10 1000 results.csv" << std::endl;
        return 1;
    }

    std::string taskset_dir = argv[1];
    int num_cores_arg = 0; // m from command line, can be -1
    int vp_count_arg = 0;
    int ap_count_arg = 0;
    double tp = 0.0;
    std::string attack_type_str = "";
    DagParser::AttackType single_attack_type_to_eval = DagParser::AttackType::NONE;
    bool run_all_relevant_types = false;
    int num_macro_runs = 0;
    int num_sim_runs_per_TH = 1000;
    bool auto_sweep_vp_ap = false;
    std::string output_csv_filepath;
    bool auto_sweep_m = false;

    try {
        num_cores_arg = std::stoi(argv[2]); // Read m
        if (num_cores_arg == -1) {
            auto_sweep_m = true;
        } else if (num_cores_arg <= 0) {
            throw std::invalid_argument("num_cores must be positive or -1 for auto-sweep.");
        }
        vp_count_arg = std::stoi(argv[3]);
        ap_count_arg = std::stoi(argv[4]);
        tp = std::stod(argv[5]);
        attack_type_str = argv[6];
        num_macro_runs = std::stoi(argv[7]);

        if (vp_count_arg == -1 && ap_count_arg == -1) {
            auto_sweep_vp_ap = true;
        } else if (vp_count_arg < 0 || ap_count_arg < 0) {
            throw std::invalid_argument("vp_count and ap_count must both be -1 for auto-sweep, or both non-negative.");
        }

        std::string upper_attack_str = attack_type_str;
        for (char &c : upper_attack_str) c = toupper(c);
        if (upper_attack_str == "ALL_RELEVANT") {
            run_all_relevant_types = true;
        } else {
            single_attack_type_to_eval = stringToAttackType(attack_type_str);
        }

        if (argc > 8) num_sim_runs_per_TH = std::stoi(argv[8]);
        if (argc > 9) output_csv_filepath = argv[9]; // Get CSV filepath
        if ((!auto_sweep_m && num_cores_arg <= 0) || tp < 0.0 || tp > 1.0 ||
                num_macro_runs <= 0 || num_sim_runs_per_TH <= 0) {
            throw std::invalid_argument("Invalid numeric argument value for cores, tp, or run counts.");
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
    try { load_success = loader.load(taskset_dir, loaded_taskset); }
    catch (const std::exception& e) { std::cerr << "Load error: " << e.what() << std::endl; return 1; }
    if (!load_success || loaded_taskset.tasks.empty() || loaded_taskset.tasks.size() != 1) {
        std::cerr << "\nFailed to load, taskset empty, or not exactly one DAG." << std::endl; return 1;
    }
    std::cout << "\nSuccessfully loaded taskset with 1 DAG." << std::endl;

    // --- Prepare for Analysis ---
    DagThreat::ThreatAnalyzer analyzer;
    std::mt19937 global_rng(std::random_device{}()); // RNG for selecting vulnerable/attacker tasks
    const DagParser::DAGTask& base_original_dag = loaded_taskset.tasks[0];
    DagParser::DAGTask base_original_dag_mutable_copy = loaded_taskset.tasks[0];
    int total_subtasks_in_dag = base_original_dag.nodes.size();

    if (total_subtasks_in_dag == 0) {
        std::cout << "Loaded DAG has no subtasks. Exiting." << std::endl;
        return 0;
    }
    if (!auto_sweep_vp_ap && (vp_count_arg > total_subtasks_in_dag || ap_count_arg > total_subtasks_in_dag)) {
        std::cerr << "Error: Specified vp_count or ap_count exceeds total subtasks in DAG ("
            << total_subtasks_in_dag << ")." << std::endl;
        return 1;
    }
    std::ofstream csv_file;
    if (!output_csv_filepath.empty()) {
        csv_file.open(output_csv_filepath, std::ios::out); // Overwrite mode
        if (!csv_file.is_open()) {
            std::cerr << "Error: Could not open CSV output file: " << output_csv_filepath << std::endl;
            // Continue without CSV output or exit? Let's continue.
            output_csv_filepath.clear(); // Disable CSV output
        } else {
            // Write CSV Header
            csv_file << "VP_Count,AP_Count,Attack_Type,Num_Macro_Runs,Num_Sim_Runs_Per_TH,Cores_M,TP_Threshold,"
                << "Avg_TH_Original,Successful_Runs_Orig,"
                << "Avg_TH_Augmented,Successful_Runs_Aug" << std::endl;
            std::cout << "Logging results to CSV: " << output_csv_filepath << std::endl;
        }
    }



    // Define the list of attack types to iterate over
    std::vector<DagParser::AttackType> attack_types_to_run_list;
    if (run_all_relevant_types) {
        attack_types_to_run_list.push_back(DagParser::AttackType::ANTERIOR);
        attack_types_to_run_list.push_back(DagParser::AttackType::POSTERIOR);
        attack_types_to_run_list.push_back(DagParser::AttackType::PINCER_DUAL_WINDOW);
        attack_types_to_run_list.push_back(DagParser::AttackType::CONCURRENT);
    } else {
        attack_types_to_run_list.push_back(single_attack_type_to_eval);
    }

    std::cout << "\n--- Starting Threat Analysis ---" << std::endl;
    std::cout << "Global Parameters: tp=" << tp
        << ", N_sim_per_TH=" << num_sim_runs_per_TH
        << ", Cores (m)=" << num_cores_arg
        << ", Macro Runs per (vp,ap,AttackType) combo=" << num_macro_runs << std::endl;


    // --- Determine vp_count and ap_count iteration ranges ---
    std::vector<int> vp_counts_to_iterate;
    std::vector<int> ap_counts_to_iterate;

    if (auto_sweep_vp_ap) {
        int step = std::max(1, static_cast<int>(std::floor(0.2 * total_subtasks_in_dag)));
        std::cout << "Auto-sweeping vp_count and ap_count with step " << step
            << " up to " << total_subtasks_in_dag << " subtasks." << std::endl;
        for (int current_val = 1; current_val <= total_subtasks_in_dag*0.7; current_val += step) {
            vp_counts_to_iterate.push_back(current_val);
        }
        for (int current_val = 1; current_val <= total_subtasks_in_dag/20; current_val += static_cast<int>((step/2))) {
            ap_counts_to_iterate.push_back(current_val);
        }
        if (vp_counts_to_iterate.empty() && total_subtasks_in_dag > 0) { // Ensure at least one iteration if step > total
            vp_counts_to_iterate.push_back(static_cast<int>(std::floor(0.2 * total_subtasks_in_dag)));
            ap_counts_to_iterate.push_back(static_cast<int>(std::floor(0.05 * total_subtasks_in_dag)));
        }
    } else {
        vp_counts_to_iterate.push_back(vp_count_arg);
        ap_counts_to_iterate.push_back(ap_count_arg);
    }


        // --- Determine m (cores) iteration range ---
    std::vector<int> m_values_to_iterate;
    if (auto_sweep_m) {
        // Pre-calculate volume and CPL on the mutable copy
        base_original_dag_mutable_copy.get_volume();
        base_original_dag_mutable_copy.get_critical_path_length();
        int m_min_graham = base_original_dag_mutable_copy.get_min_cores_graham_bound();

        if (m_min_graham == -1) {
            std::cerr << "Error: DAG is unschedulable by Graham's bound even with infinite cores. Cannot auto-sweep m." << std::endl;
            return 1;
        }
        if (m_min_graham == 0) m_min_graham = 1; // Should be at least 1

        int m_max_graham_sweep = 2 * m_min_graham;
        std::cout << "Auto-sweeping num_cores (m) from " << m_min_graham << " to " << m_max_graham_sweep << std::endl;
        int step_m = std::max(1, static_cast<int>(std::floor(0.2 * m_min_graham)));
        for (int current_m_val = m_min_graham; current_m_val <= m_max_graham_sweep; current_m_val+=step_m) {
            if (current_m_val <= 0) continue; // Should not happen if m_min_graham >=1
            m_values_to_iterate.push_back(current_m_val);
        }
        if (m_values_to_iterate.empty()){
             std::cerr << "Error: No valid m values generated for auto-sweep. m_min_graham=" << m_min_graham << std::endl;
             return 1;
        }
    } else {
        m_values_to_iterate.push_back(num_cores_arg);
    }

    for (int current_m_for_analysis : m_values_to_iterate) {
        std::cout << "\n\n####################################################################" << std::endl;
        std::cout << "Evaluating for Number of Cores (m) = " << current_m_for_analysis << std::endl;
        std::cout << "####################################################################" << std::endl;

        // --- Outermost Loops: vp_count, then ap_count ---
        for (int current_vp_count : vp_counts_to_iterate) {
            for (int current_ap_count : ap_counts_to_iterate) {
                std::cout << "\n\n====================================================================" << std::endl;
                std::cout << "Evaluating for vp_count = " << current_vp_count
                    << ", ap_count = " << current_ap_count << std::endl;
                std::cout << "====================================================================" << std::endl;

                // --- Loop for each Attack Type ---
                for (DagParser::AttackType current_attack_type : attack_types_to_run_list) {
                    std::cout << "\n<<<<<<<<<< Evaluating Attack Type: "
                        << attackTypeToString(current_attack_type) << " >>>>>>>>>>" << std::endl;

                    std::vector<double> th_originals_for_combo;
                    std::vector<double> th_augmenteds_for_combo;

                    // --- Loop for Macro Runs (repeated selections of vulnerable/attacker subtasks) ---
                    // openmp paraallelize
#pragma omp parallel
                    {
                        DagParser::DAGTask thread_local_dag_copy; // Each thread gets its own copy
                        DagParser::TaskSet thread_local_taskset;  // Each thread gets its own taskset wrapper
                        std::mt19937 thread_local_rng(std::random_device{}() + omp_get_thread_num()); // Thread-safe RNG

#pragma omp for
                        for (int macro_run = 0; macro_run < num_macro_runs; ++macro_run) {
                            // std::cout << "Thread " << omp_get_thread_num() << " starting macro_run " << macro_run << std::endl; // Debug
                            thread_local_dag_copy = base_original_dag; // Create a fresh copy for this thread's iteration
                            thread_local_dag_copy.mark_subtasks_randomly(current_vp_count, current_ap_count, thread_local_rng);

                            thread_local_taskset.tasks.clear(); // Clear from previous iteration if any
                            thread_local_taskset.tasks.push_back(thread_local_dag_copy);

                            double res_orig = -1.0, res_aug = -1.0;
                            try {
                                unsigned int th_calc_seed = thread_local_rng();
                                DagThreat::ThreatAnalysisResult results = analyzer.calculate_comparative_TH(
                                        thread_local_taskset,
                                        current_vp_count,
                                        current_ap_count,
                                        tp,
                                        current_attack_type,
                                        current_m_for_analysis,
                                        num_sim_runs_per_TH,
                                        th_calc_seed
                                        );
                                res_orig = results.th_original_dag;
                                res_aug = results.th_augmented_dag;
                            } catch (const std::exception& e) {
                                // Critical section for cerr if multiple threads might write
#pragma omp critical
                                {
                                    std::cerr << "  Error in (Thread " << omp_get_thread_num()
                                        << ", Macro Run " << macro_run + 1 << ") for (vp=" << current_vp_count
                                        << ", ap=" << current_ap_count << ", Attack=" << attackTypeToString(current_attack_type)
                                        << "): " << e.what() << std::endl;
                                }
                            }
                            // Safely add results to shared vectors
#pragma omp critical
                            {
                                th_originals_for_combo.push_back(res_orig);
                                th_augmenteds_for_combo.push_back(res_aug);
                            }
                        } // End Macro Runs Loop (omp for)
                    } // End Parallel Region
                      // --- Aggregate and Print Results for the Current (vp, ap, AttackType) Combo ---
                    double avg_th_orig = 0.0; int count_orig = 0;
                    for (double val : th_originals_for_combo) if (val >= 0.0) { avg_th_orig += val; count_orig++; }
                    if (count_orig > 0) avg_th_orig /= count_orig; else avg_th_orig = -1.0; // Use -1 for no valid runs

                    double avg_th_aug = 0.0; int count_aug = 0;
                    for (double val : th_augmenteds_for_combo) if (val >= 0.0) { avg_th_aug += val; count_aug++; }
                    if (count_aug > 0) avg_th_aug /= count_aug; else avg_th_aug = -1.0; // Use -1 for no valid runs
                    std::cout << "\n--- Aggregated Results for (vp=" << current_vp_count
                        << ", ap=" << current_ap_count << ", Attack=" << attackTypeToString(current_attack_type)
                        << ") (Over " << num_macro_runs << " Macro Runs) ---" << std::endl;

                    if (count_orig > 0) std::cout << "Average TH for ORIGINAL DAG   : " << std::fixed << std::setprecision(6) << avg_th_orig << " (from " << count_orig << " runs)" << std::endl;
                    else std::cout << "No successful runs for ORIGINAL DAG TH." << std::endl;
                    if (count_aug > 0) std::cout << "Average TH for AUGMENTED DAG: " << std::fixed << std::setprecision(6) << avg_th_aug << " (from " << count_aug << " runs)" << std::endl;
                    else std::cout << "No successful runs for AUGMENTED DAG TH." << std::endl;    // --- Write to CSV File ---

                    if (csv_file.is_open()) {
                        csv_file << current_vp_count << ","
                            << current_ap_count << ","
                            << attackTypeToString(current_attack_type) << ","
                            << num_macro_runs << ","
                            << num_sim_runs_per_TH << ","
                            << current_m_for_analysis << "," // Added Cores_M
                            << tp << ","            // Added TP_Threshold
                            << std::fixed << std::setprecision(8) // Use higher precision for CSV
                            << (count_orig > 0 ? avg_th_orig : -1.0) << "," // Use -1.0 if no valid runs
                            << count_orig << ","
                            << (count_aug > 0 ? avg_th_aug : -1.0) << "," // Use -1.0 if no valid runs
                            << count_aug
                            << std::endl;
                    }
                    std::cout << "--------------------------------------------------------------------" << std::endl;
                } // End Attack Types Loop
            } // End ap_count Loop
        } // End vp_count Loop
    } // End m Loop
    if (csv_file.is_open()) {
        csv_file.close();
        std::cout << "\nResults also written to: " << output_csv_filepath << std::endl;
    }

    std::cout << "\nAll tests finished." << std::endl;
    return 0;
}
