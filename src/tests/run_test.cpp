#include "tests.h"

#include <vector>

// Correctness suite behind `--test all`: every registered test that asserts
// its result and finishes in seconds to a few minutes. The timed benchmarks
// (tree_bench, tree_bench_g32, cuckoo_bench), the informational cpu_info and
// the plan_params search are excluded; merkle_benchmarks and
// layer_layout_sweep are main.cpp entry points, not PirTest members.
static const std::vector<std::string> kRegressionTests = {
    "barrett", "utils_arith", "noise_sampling", "rlwe_enc", "hexl_ntt",
    "bfv", "decrypt_mod_q", "mod_switch", "bv_ks", "ext_prod",
    "ext_prod_mux", "fst_dim", "db_shape", "runtime_layout", "fast_expand",
    "pir", "pir_profile", "server_loader", "shared_session",
    "tree_index", "tree_query", "tree_select", "tree_rotate", "tree_project",
    "tree_kernel", "tree_e2e", "tree_g32", "tree_compress",
    "merkle_baseline", "merkle_benchmark_stats", "layer_layout_planner",
    "merkle_integration", "cuckoo_batch",
};

void PirTest::run_test(const std::string &test_name) {
  if (test_name == "all") {
    std::vector<std::string> failures, not_applicable;
    for (const std::string &name : kRegressionTests) {
      try {
        run_test(name);
      } catch (const TestNotApplicable &why) {
        std::cout << "NOT APPLICABLE " << name << ": " << why.what() << '\n';
        not_applicable.push_back(name + ": " + why.what());
      } catch (const std::exception &error) {
        std::cerr << "FAILED " << name << ": " << error.what() << '\n';
        failures.push_back(name + ": " + error.what());
      }
    }
    const size_t applicable = kRegressionTests.size() - not_applicable.size();
    std::cout << "Regression suite: " << applicable - failures.size() << "/"
              << applicable << " applicable tests passed";
    if (!not_applicable.empty()) {
      std::cout << ", " << not_applicable.size()
                << " not applicable to this build:";
      for (const std::string &n : not_applicable) std::cout << "\n  " << n;
    }
    std::cout << '\n';
    if (!failures.empty()) {
      std::string message = "regression failures:";
      for (const std::string &f : failures) message += "\n  " + f;
      throw std::runtime_error(message);
    }
    return;
  }
  std::cout << "Running test: " << test_name << std::endl;

  if (test_name == "pir")                    test_pir();
  else if (test_name == "bfv")               bfv_example();
  else if (test_name == "ext_prod")          test_external_product();
  else if (test_name == "ext_prod_mux")      test_ext_prod_mux();
  else if (test_name == "fst_dim")           test_fst_dim_mult();
  else if (test_name == "fast_expand")       test_fast_expand_query();
  else if (test_name == "tree_index")        test_tree_index();
  else if (test_name == "tree_query")        test_tree_query();
  else if (test_name == "tree_select")       test_tree_select();
  else if (test_name == "tree_rotate")       test_tree_rotate();
  else if (test_name == "tree_project")      test_tree_project();
  else if (test_name == "tree_e2e")          test_tree_e2e();
  else if (test_name == "tree_kernel")       test_tree_kernel();
  else if (test_name == "tree_bench")        test_tree_benchmark();
  else if (test_name == "tree_g32")          test_tree_g32();
  else if (test_name == "tree_bench_g32")    test_tree_benchmark_g32();
  else if (test_name == "tree_compress")     test_tree_compress();
  else if (test_name == "cuckoo_batch")      test_cuckoo_batch();
  else if (test_name == "cuckoo_bench")      test_cuckoo_benchmark();
  else if (test_name == "decrypt_mod_q")     test_decrypt_mod_q();
  else if (test_name == "mod_switch")        test_mod_switch();
  else if (test_name == "db_shape")          test_db_shape();
  else if (test_name == "runtime_layout")     test_runtime_layout();
  else if (test_name == "merkle_baseline")    test_merkle_baseline();
  else if (test_name == "server_loader")       test_server_loader();
  else if (test_name == "shared_session")      test_shared_session();
  else if (test_name == "merkle_benchmark_stats") test_merkle_benchmark_stats();
  else if (test_name == "merkle_integration")  test_merkle_integration();
  else if (test_name == "pir_profile")         test_pir_profile();
  else if (test_name == "layer_layout_planner") test_layer_layout_planner();
  else if (test_name == "bv_ks")             test_bv_keyswitch();
  else if (test_name == "cpu_info")          print_cpu_info();
  else if (test_name == "hexl_ntt")          test_hexl_ntt();
  else if (test_name == "utils_arith")       test_utils_arith();
  else if (test_name == "noise_sampling")    test_noise_sampling();
  else if (test_name == "rlwe_enc")          test_rlwe_enc();
  else if (test_name == "barrett")           test_barrett();
  else if (test_name == "plan_params")       plan_params();
  else {
    throw std::invalid_argument("Unknown test: " + test_name);
  }
}
