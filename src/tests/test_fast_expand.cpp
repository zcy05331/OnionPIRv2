#include "tests.h"

#include <random>

// fast_expand_qry on the packed standard query: the packed ciphertext must
// carry its non-zero slot at BitRev(idx mod fst_dim, h) (the fast expansion
// consumes a bit-reversed slot order), and after expansion the first-dimension
// leaves must be an exact BFV one-hot at idx mod fst_dim, i.e. leaf j
// decrypts to the constant [j == idx mod fst_dim] with every other
// coefficient zero. Checked for the first row, the last row and one seeded
// interior row of the default layout.
void PirTest::test_fast_expand_query() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  const size_t fst_dim_sz = pir_params.get_fst_dim_sz();
  const size_t useful_cnt =
      fst_dim_sz + pir_params.get_l() * (pir_params.get_num_dims() - 1);
  const size_t num_pt = pir_params.get_num_pt();
  const size_t expan_height = pir_params.get_expan_height();

  PirClient client(pir_params);
  PirServer server(pir_params);
  const size_t client_id = client.get_client_id();
  pir_params.print_params();

  server.set_client_bv_galois_key(client_id, client.create_bv_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  {
    RlweCt zero_ct = client.fresh_zero_ct();
    const int budget = client.noise_budget(zero_ct);
    BENCH_PRINT("fresh zero noise budget: " << budget << " bits");
    require_test(budget > 0, "fresh zero ciphertext has no noise budget");
    const RlwePt zero_pt = client.decrypt_ct(zero_ct);
    for (uint64_t v : zero_pt.data) {
      require_test(v == 0, "fresh zero ciphertext does not decrypt to zero");
    }
  }

  std::mt19937_64 rng(0x66617374ULL);
  const std::vector<size_t> query_indices = {0, num_pt - 1,
                                             rng() % num_pt};
  for (size_t query_idx : query_indices) {
    const size_t target = query_idx % fst_dim_sz;
    RlweCt fast_query = client.fast_generate_query(query_idx);

    // Packed layout: the only non-zero slots are the bit-reversed first-dim
    // slot and the bit-reversed RGSW selector rows above fst_dim_sz.
    {
      const RlwePt packed = client.decrypt_ct(fast_query);
      const size_t reversed = utils::bit_reverse(target, expan_height);
      require_test(packed.data[reversed] != 0,
                   "packed query lacks the bit-reversed first-dim slot");
      for (size_t j = 0; j < fst_dim_sz; ++j) {
        if (j == target) continue;
        require_test(packed.data[utils::bit_reverse(j, expan_height)] == 0,
                     "packed query has a stray first-dim slot");
      }
    }

    auto fast_exp_q = server.fast_expand_qry(client_id, fast_query);
    require_test(fast_exp_q.size() >= useful_cnt,
                 "expansion returned fewer leaves than the useful count");
    const int budget = client.noise_budget(fast_exp_q[target]);
    BENCH_PRINT("query " << query_idx << ": expanded leaf noise budget "
                << budget << " bits");
    require_test(budget > 0, "expanded leaf has no noise budget");

    for (size_t j = 0; j < fst_dim_sz; ++j) {
      const RlwePt leaf = client.decrypt_ct(fast_exp_q[j]);
      require_test(leaf.data[0] == (j == target ? 1U : 0U),
                   "expanded first-dim leaf is not the one-hot constant");
      for (size_t i = 1; i < leaf.data.size(); ++i) {
        require_test(leaf.data[i] == 0,
                     "expanded first-dim leaf is not a constant");
      }
    }
  }
  PRINT_BAR;
}
