#include "taskset_loader.h"
#include "taskset.h"
#include "dag_task.h"
#include "threat_analyzer.h"
#include <iostream>
#include <fstream> // For CSV output
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <random>
#include <numeric> // For std::accumulate, std::iota
#include <cmath>   // For std::floor, std::max
#include <map>
#include <set>     // For std::set
#include <omp.h>   // For OpenMP

// Helper to convert string to AttackType enum and detect ENTROPY_ONLY mode
DagParser::AttackType stringToAttackType(const std::string& s, bool& is_entropy_only_mode) {
    std::string upper_s = s;
    for (char &c : upper_s) c = toupper(c);

    is_entropy_only_mode = false; // Reset flag

    if (upper_s == "ANTERIOR") return DagParser::AttackType::ANTERIOR;
    if (upper_s == "POSTERIOR") return DagParser::AttackType::POSTERIOR;
    if (upper_s == "PINCER_SINGLE") return DagParser::AttackType::PINCER_SINGLE_WINDOW;
    if (upper_s == "PINCER_DUAL") return DagParser::AttackType::PINCER_DUAL_WINDOW;
    if (upper_s == "CONCURRENT") return DagParser::AttackType::CONCURRENT;
    if (upper_s == "NONE") return DagParser::AttackType::NONE;
    if (upper_s == "ALL_RELEVANT") return static_cast<DagParser::AttackType>(-1); // Special value for ALL TH types
    if (upper_s == "ENTROPY_ONLY") { // Special keyword for entropy-only mode
        is_entropy_only_mode = true;
        return DagParser::AttackType::NONE; // Return a default, won't be used for TH calc
    }
    throw std::invalid_argument("Unknown AttackType or Mode string: " + s);
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
    const int MIN_REQUIRED_ARGS_TH = 8;
    const int MIN_REQUIRED_ARGS_ENTROPY_BASE = 4; // dir, cores, "ENTROPY_ONLY"

    if (argc < MIN_REQUIRED_ARGS_ENTROPY_BASE) { // Minimum for any mode
        std::cerr << "Usage (TH Mode): " << argv[0]
                  << " <taskset_dir> <num_cores|-1> <vp_count|-1> <ap_count|-1> <tp> <attack_type|ALL_RELEVANT> <num_macro_runs> [num_sim_runs_per_TH] [output_csv_file]"
                  << std::endl;
        std::cerr << "Usage (Entropy-Only Mode): " << argv[0]
                  << " <taskset_dir> <num_cores> ENTROPY_ONLY [num_entropy_runs] [output_csv_file]"
                  << std::endl;
        return 1;
    }

    std::string taskset_dir = argv[1];
    int num_cores_arg = 0;
    int vp_count_arg = 0;
    int ap_count_arg = 0;
    double tp = 0.0;
    std::string mode_or_attack_type_str = ""; // Will hold argv[3] or argv[6]
    DagParser::AttackType single_attack_type_to_eval = DagParser::AttackType::NONE;
    bool run_all_relevant_th_types = false;
    bool entropy_only_mode = false;
    int num_macro_runs = 1;
    int num_runs_for_estimation = 1000; // Default for TH sim runs / entropy runs
    bool auto_sweep_vp_ap = false;
    std::string output_csv_filepath;
    bool auto_sweep_m = false;

    try {
        num_cores_arg = std::stoi(argv[2]); // Common for both modes initially

        // Determine mode based on the argument that specifies attack type or ENTROPY_ONLY
        // For TH mode, this is argv[6]. For Entropy mode, this is argv[3].
        if (argc >= 4) { // Enough args for mode string in entropy mode
             std::string potential_mode_str = argv[3];
             std::string upper_mode_str = potential_mode_str;
             for(char &c : upper_mode_str) c = toupper(c);
             if (upper_mode_str == "ENTROPY_ONLY") {
                 entropy_only_mode = true;
                 mode_or_attack_type_str = potential_mode_str; // Store it
             }
        }

        if (entropy_only_mode) {
            if (num_cores_arg <= 0) throw std::invalid_argument("num_cores must be positive for entropy mode.");
            if (argc > 4) num_runs_for_estimation = std::stoi(argv[4]);
            if (argc > 5) output_csv_filepath = argv[5];
        } else { // TH Calculation Mode
            if (argc < MIN_REQUIRED_ARGS_TH) {
                 std::cerr << "Insufficient arguments for TH calculation mode." << std::endl;
                 std::cerr << "Usage (TH Mode): " << argv[0]
                  << " <taskset_dir> <num_cores|-1> <vp_count|-1> <ap_count|-1> <tp> <attack_type|ALL_RELEVANT> <num_macro_runs> [num_sim_runs_per_TH] [output_csv_file]"
                  << std::endl;
                 return 1;
            }
            // num_cores_arg already parsed
            vp_count_arg = std::stoi(argv[3]);
            ap_count_arg = std::stoi(argv[4]);
            tp = std::stod(argv[5]);
            mode_or_attack_type_str = argv[6]; // This is the actual attack type string for TH
            num_macro_runs = std::stoi(argv[7]);

            if (num_cores_arg == -1) auto_sweep_m = true;
            else if (num_cores_arg <= 0) throw std::invalid_argument("num_cores must be positive or -1 for TH mode.");

            if (vp_count_arg == -1 && ap_count_arg == -1) auto_sweep_vp_ap = true;
            else if (vp_count_arg < 0 || ap_count_arg < 0) throw std::invalid_argument("vp_count and ap_count must both be -1 for auto-sweep, or both non-negative for TH mode.");

            std::string upper_attack_str = mode_or_attack_type_str;
            for (char &c : upper_attack_str) c = toupper(c);
            if (upper_attack_str == "ALL_RELEVANT") run_all_relevant_th_types = true;
            else single_attack_type_to_eval = stringToAttackType(mode_or_attack_type_str, entropy_only_mode); // entropy_only_mode will be false here

            if (argc > 8) num_runs_for_estimation = std::stoi(argv[8]);
            if (argc > 9) output_csv_filepath = argv[9];

            if (tp < 0.0 || tp > 1.0 || num_macro_runs <= 0 || num_runs_for_estimation <= 0) {
                throw std::invalid_argument("Invalid numeric argument value for tp or run counts in TH mode.");
            }
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
    try { load_success = loader.load(taskset_dir, loaded_taskset); }
    catch (const std::exception& e) { std::cerr << "Load error: " << e.what() << std::endl; return 1; }
    if (!load_success || loaded_taskset.tasks.empty() || loaded_taskset.tasks.size() != 1) {
         std::cerr << "\nFailed to load, taskset empty, or not exactly one DAG." << std::endl; return 1;
    }
    std::cout << "\nSuccessfully loaded taskset with 1 DAG." << std::endl;

    DagThreat::ThreatAnalyzer analyzer;
    std::mt19937 global_rng(std::random_device{}());
    DagParser::DAGTask base_original_dag_mutable_copy = loaded_taskset.tasks[0];
    int total_subtasks_in_dag = base_original_dag_mutable_copy.nodes.size();

    if (total_subtasks_in_dag == 0) { std::cout << "Loaded DAG has no subtasks. Exiting." << std::endl; return 0; }

    std::ofstream csv_file;
    if (!output_csv_filepath.empty()) {
        csv_file.open(output_csv_filepath, std::ios::out);
        if (!csv_file.is_open()) {
            std::cerr << "Error: Could not open CSV output file: " << output_csv_filepath << std::endl;
            output_csv_filepath.clear();
        } else {
            if (entropy_only_mode) {
                csv_file << "Num_Cores_M,Num_Entropy_Runs,Original_Subtask_Index,Original_Dot_ID,H_Dist\n";
            } else { // TH Mode header
                csv_file << "VP_Count,AP_Count,Attack_Type,Num_Macro_Runs,Num_Sim_Runs_Per_TH,Cores_M,TP_Threshold,"
                         << "Avg_TH_Original,Successful_Runs_Orig,"
                         << "Avg_TH_Augmented,Successful_Runs_Aug" << std::endl;
            }
            std::cout << "Logging results to CSV: " << output_csv_filepath << std::endl;
        }
    }

    // ==========================================================================================
    // --- Main Logic Branch: Entropy-Only OR TH Calculation ---
    // ==========================================================================================
    if (entropy_only_mode) {
        std::cout << "\n--- Calculating Task Distribution Entropy ONLY ---" << std::endl;
        std::cout << "Using m = " << num_cores_arg << ", N_entropy_runs = " << num_runs_for_estimation << std::endl;

        std::set<int> all_original_subtask_indices;
        for (size_t i = 0; i < base_original_dag_mutable_copy.nodes.size(); ++i) {
            all_original_subtask_indices.insert(i);
        }

        try {
            DagParser::DAGTask dag_for_entropy_calc = base_original_dag_mutable_copy;
            unsigned int entropy_rng_seed = global_rng();

            std::map<int, double> entropies = analyzer.calculate_task_distribution_entropy(
                dag_for_entropy_calc,
                all_original_subtask_indices,
                num_cores_arg,
                num_runs_for_estimation,
                entropy_rng_seed
            );

            std::cout << "\n--- Task Distribution Entropies (H_dist) ---" << std::endl;
            std::cout << std::fixed << std::setprecision(6);
            for (const auto& pair : entropies) {
                std::cout << "  Original Subtask Index " << std::setw(3) << pair.first
                          << " (DotID " << std::setw(3) << base_original_dag_mutable_copy.nodes[pair.first].original_dot_id
                          << "): H_dist = " << pair.second << std::endl;
                if (csv_file.is_open()) {
                    csv_file << num_cores_arg << ","
                             << num_runs_for_estimation << ","
                             << pair.first << ","
                             << base_original_dag_mutable_copy.nodes[pair.first].original_dot_id << ","
                             << pair.second << std::endl;
                }
            }
            std::cout << "--------------------------------------------" << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "Error calculating task distribution entropy: " << e.what() << std::endl;
        }

    } else { // --- TH Calculation Mode ---
        if (!auto_sweep_vp_ap && (vp_count_arg > total_subtasks_in_dag || ap_count_arg > total_subtasks_in_dag)) {
            std::cerr << "Error: Specified vp_count or ap_count exceeds total subtasks in DAG ("
                      << total_subtasks_in_dag << ")." << std::endl;
            if(csv_file.is_open()) csv_file.close();
            return 1;
        }

        std::vector<DagParser::AttackType> attack_types_to_run_list;
        if (run_all_relevant_th_types) {
            attack_types_to_run_list.push_back(DagParser::AttackType::ANTERIOR);
            attack_types_to_run_list.push_back(DagParser::AttackType::POSTERIOR);
            attack_types_to_run_list.push_back(DagParser::AttackType::PINCER_DUAL_WINDOW);
            attack_types_to_run_list.push_back(DagParser::AttackType::CONCURRENT);
        } else {
            attack_types_to_run_list.push_back(single_attack_type_to_eval);
        }

        std::cout << "\n--- Starting TH Threat Analysis ---" << std::endl;
        std::cout << "Global Parameters: tp=" << tp
                  << ", N_sim_per_TH=" << num_runs_for_estimation
                  << ", Macro Runs per (vp,ap,AttackType,m) combo=" << num_macro_runs << std::endl;


        std::vector<int> vp_counts_to_iterate;
        std::vector<int> ap_counts_to_iterate;
        int max_ap_limit = std::max(1, total_subtasks_in_dag / 2);

        if (auto_sweep_vp_ap) {
            int step = std::max(1, static_cast<int>(std::floor(0.05 * total_subtasks_in_dag)));
            std::cout << "Auto-sweeping vp_count with step " << step << " up to " << total_subtasks_in_dag << " subtasks." << std::endl;
            std::cout << "Auto-sweeping ap_count with step " << step << " up to " << max_ap_limit << " subtasks (max half of total)." << std::endl;
            for (int cv = step; cv <= total_subtasks_in_dag; cv += step) vp_counts_to_iterate.push_back(cv);
            if (vp_counts_to_iterate.empty() && total_subtasks_in_dag > 0) vp_counts_to_iterate.push_back(total_subtasks_in_dag);
            for (int ca = step; ca <= max_ap_limit; ca += step) ap_counts_to_iterate.push_back(ca);
            if (ap_counts_to_iterate.empty() && max_ap_limit > 0) ap_counts_to_iterate.push_back(max_ap_limit);
        } else {
            vp_counts_to_iterate.push_back(std::min(vp_count_arg, total_subtasks_in_dag));
            ap_counts_to_iterate.push_back(std::min(ap_count_arg, max_ap_limit));
        }
        if (ap_counts_to_iterate.empty() && total_subtasks_in_dag > 0) ap_counts_to_iterate.push_back(std::min(1,total_subtasks_in_dag));


        std::vector<int> m_values_to_iterate;
        if (auto_sweep_m) {
            DagParser::DAGTask temp_dag_for_m_calc = base_original_dag_mutable_copy;
            temp_dag_for_m_calc.get_volume(); temp_dag_for_m_calc.get_critical_path_length(); // Pre-cache
            int m_min_graham = temp_dag_for_m_calc.get_min_cores_graham_bound();
            if (m_min_graham == -1) { /* ... error ... */ return 1; }
            if (m_min_graham == 0) m_min_graham = 1;
            int m_max_graham_sweep = 2 * m_min_graham;
            std::cout << "Auto-sweeping num_cores (m) from " << m_min_graham << " to " << m_max_graham_sweep << std::endl;
            for (int cm = m_min_graham; cm <= m_max_graham_sweep; ++cm) if (cm > 0) m_values_to_iterate.push_back(cm);
            if (m_values_to_iterate.empty()){ /* ... error ... */ return 1; }
        } else {
            m_values_to_iterate.push_back(num_cores_arg);
        }

        // --- Main TH Loops ---
        for (int current_m_for_analysis : m_values_to_iterate) {
          std::cout << "\n\n####################################################################" << std::endl;
          std::cout << "Evaluating for Number of Cores (m) = " << current_m_for_analysis << std::endl;
          std::cout << "####################################################################" << std::endl;
          for (int current_vp_count : vp_counts_to_iterate) {
            for (int current_ap_count : ap_counts_to_iterate) {
              std::cout << "\n\n====================================================================" << std::endl;
              std::cout << "Evaluating for vp_count = " << current_vp_count
                        << ", ap_count = " << current_ap_count << " (with m = " << current_m_for_analysis << ")" << std::endl;
              std::cout << "====================================================================" << std::endl;
              for (DagParser::AttackType current_attack_type : attack_types_to_run_list) {
                std::cout << "\n<<<<<<<<<< Evaluating Attack Type: "
                          << attackTypeToString(current_attack_type) << " >>>>>>>>>>" << std::endl;

                std::vector<double> th_originals_for_combo;
                std::vector<double> th_augmenteds_for_combo;
                th_originals_for_combo.reserve(num_macro_runs);
                th_augmenteds_for_combo.reserve(num_macro_runs);

                #pragma omp parallel
                {
                    DagParser::DAGTask thread_local_dag_copy;
                    DagParser::TaskSet thread_local_taskset;
                    std::mt19937 thread_local_rng(std::random_device{}() + omp_get_thread_num());

                    #pragma omp for
                    for (int macro_run = 0; macro_run < num_macro_runs; ++macro_run) {
                        thread_local_dag_copy = base_original_dag_mutable_copy;
                        thread_local_dag_copy.mark_subtasks_randomly(current_vp_count, current_ap_count, thread_local_rng);
                        thread_local_taskset.tasks.clear();
                        thread_local_taskset.tasks.push_back(thread_local_dag_copy);

                        double res_orig = -1.0, res_aug = -1.0;
                        try {
                            unsigned int th_calc_seed = thread_local_rng();
                            DagThreat::ThreatAnalysisResult results = analyzer.calculate_comparative_TH(
                                    thread_local_taskset, current_vp_count, current_ap_count, tp,
                                    current_attack_type, current_m_for_analysis,
                                    num_runs_for_estimation, th_calc_seed);
                            res_orig = results.th_original_dag;
                            res_aug = results.th_augmented_dag;
                        } catch (const std::exception& e) {
                            #pragma omp critical
                            { std::cerr << "  Error in (Thread " << omp_get_thread_num() << ", Macro Run " << macro_run + 1 << ") ...: " << e.what() << std::endl; }
                        }
                        #pragma omp critical
                        {
                            th_originals_for_combo.push_back(res_orig);
                            th_augmenteds_for_combo.push_back(res_aug);
                        }
                    }
                } // End Parallel Region

                double avg_th_orig = 0.0; int count_orig = 0;
                for (double val : th_originals_for_combo) if (val >= 0.0) { avg_th_orig += val; count_orig++; }
                if (count_orig > 0) avg_th_orig /= count_orig; else avg_th_orig = -1.0;

                double avg_th_aug = 0.0; int count_aug = 0;
                for (double val : th_augmenteds_for_combo) if (val >= 0.0) { avg_th_aug += val; count_aug++; }
                if (count_aug > 0) avg_th_aug /= count_aug; else avg_th_aug = -1.0;

                std::cout << "\n--- Aggregated Results for (m=" << current_m_for_analysis << ", vp=" << current_vp_count
                          << ", ap=" << current_ap_count << ", Attack=" << attackTypeToString(current_attack_type)
                          << ") (Over " << num_macro_runs << " Macro Runs) ---" << std::endl;
                if (count_orig > 0) std::cout << "Average TH for ORIGINAL DAG   : " << std::fixed << std::setprecision(6) << avg_th_orig << " (from " << count_orig << " runs)" << std::endl;
                else std::cout << "No successful runs for ORIGINAL DAG TH." << std::endl;
                if (count_aug > 0) std::cout << "Average TH for AUGMENTED DAG: " << std::fixed << std::setprecision(6) << avg_th_aug << " (from " << count_aug << " runs)" << std::endl;
                else std::cout << "No successful runs for AUGMENTED DAG TH." << std::endl;

                if (csv_file.is_open()) {
                    csv_file << current_vp_count << "," << current_ap_count << ","
                             << attackTypeToString(current_attack_type) << ","
                             << num_macro_runs << "," << num_runs_for_estimation << ","
                             << current_m_for_analysis << "," << tp << ","
                             << std::fixed << std::setprecision(8)
                             << (count_orig > 0 ? avg_th_orig : -1.0) << "," << count_orig << ","
                             << (count_aug > 0 ? avg_th_aug : -1.0) << "," << count_aug
                             << std::endl;
                }
                std::cout << "--------------------------------------------------------------------" << std::endl;
              } // End Attack Types Loop
            } // End ap_count Loop
          } // End vp_count Loop
        } // End m_values_to_iterate Loop
    } // End TH Calculation Mode

    if (csv_file.is_open()) {
        csv_file.close();
        std::cout << "\nResults also written to: " << output_csv_filepath << std::endl;
    }

    std::cout << "\nAll tests finished." << std::endl;
    return 0;
}
