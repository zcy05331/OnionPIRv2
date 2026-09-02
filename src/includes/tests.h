#pragma once

#include <string>

// Common includes used by most tests
#include "gsw.h"
#include "pir.h"
#include "server.h"
#include "client.h"
#include "utils.h"
#include "logging.h"
#include "matrix.h"

#include <cassert>
#include <iostream>
#include <bitset>
#include <stdexcept>

inline void require_test(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline void print_throughput(const std::string &name, const size_t db_size) {
  double avg_time = GET_AVG_TIME(name);
  double throughput = db_size / (avg_time * 1000);
  BENCH_PRINT(name << ": " << throughput << " MB/s");
}

class PirTest {
  public:
    size_t num_experiments = 10;

    void run_test(const std::string &test_name);

    // ! the main test for PIR
    void test_pir();

    // ======================== BFV & GSW tests ========================
    void bfv_example();
    void test_external_product();
    void test_decrypt_mod_q();
    void test_ext_prod_mux();

    // ======================== Matrix tests ========================
    // simulation of the first dimension multiplication
    void test_fst_dim_mult();

    // ======================== System Information ========================
    void print_cpu_info();

    // ======================== Other tests ========================
    void test_fast_expand_query();
    // ======================== Tree PIR tests ========================
    // (gamma, alpha, beta) index math and public level plans (pure arithmetic).
    void test_tree_index();
    // Packed tree query -> ExpandBFV -> order/scale -> RGSW -> isolated CMux.
    void test_tree_query();
    // Milestone 2: level packing, alpha pyramid, SelectLevel == D_l[p_l].
    void test_tree_select();
    // Milestone 3: MulXPow oracle, RotSelect, PrivateRotateLevel alignment.
    void test_tree_rotate();
    // Milestone 3: projection map for every depth plus the rotate+project gate.
    void test_tree_project();
    // Milestone 4: full path pipeline, chunk packing, client decode.
    void test_tree_e2e();
    // Milestone 6: scalar vs NTT first-dimension kernels, bit-for-bit.
    void test_tree_kernel();
    // Timed MVP path benchmark at the baseline workload scale (2^24 leaves).
    void test_tree_benchmark();
    // Real-scenario g=32: 32-byte nodes end to end, plus its benchmark.
    void test_tree_g32();
    void test_tree_benchmark_g32();
    // Milestone 7: d=2 ring-switched response compression gate.
    void test_tree_compress();
    // Cuckoo-hash batch PIR baseline: correctness gate and L=22 benchmark.
    void test_cuckoo_batch();
    void test_cuckoo_benchmark();
    void test_mod_switch();
    void test_db_shape();
    void test_runtime_layout();
    void test_merkle_baseline();
    void test_server_loader();
    void test_shared_session();
    void test_merkle_benchmark_stats();
    void test_merkle_integration();
    // Stage-profiled make_query is bit-for-bit the plain pipeline.
    void test_pir_profile();
    // Layer layout candidates, features, Pareto frontier, profile selection.
    void test_layer_layout_planner();
    void test_bv_keyswitch();
    void test_hexl_ntt();
    void test_utils_arith();
    void test_noise_sampling();
    void test_rlwe_enc();
    void test_barrett();

    // Search (tree_height, num_queries, num_other_dims) for minimum total
    // communication in each (QueryMode, GswSource) combination, given the
    // current config's num_pt, L_EP, L_KEY and BFV ciphertext size.
    void plan_params();
};
