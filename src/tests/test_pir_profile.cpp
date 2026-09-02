#include "tests.h"

#include <chrono>
#include <vector>

// make_query_profiled must be the same pipeline as make_query: for one packed
// query evaluated twice (a copy each), the responses are bit-for-bit equal,
// and every profiled stage that runs is positive.
void PirTest::test_pir_profile() {
  print_func_name(__FUNCTION__);
  // Ragged multidimensional layout: 43 plaintexts under expansion height 5
  // exercises expansion pruning, RGSW completion, the first dimension and
  // the remaining-dimension CMux tree.
  const PirParams params = PirParams().with_layout({43, 5, true});
  PirClient client(params);
  SharedPirSessionKeys keys = client.create_session_keys();
  PirServer server(params);
  server.set_client_session_keys(client.get_client_id(), keys);
  const uint64_t plain_mod = params.get_plain_mod();
  PlaintextSource source = [&](size_t index, RlwePt &out) {
    out.data.resize(params.get_poly_degree());
    for (size_t c = 0; c < out.data.size(); ++c) {
      out.data[c] = (31 * index + 7 * c + 5) % plain_mod;
    }
  };
  server.load_data(params.get_target_num_pt(), source);

  RlweCt packed = client.fast_generate_query(params, 29);
  RlweCt plain_query = packed;
  RlweCt profiled_query = packed;
  RlweCt plain = server.make_query(client.get_client_id(), plain_query);
  PirPipelineProfile profile;
  RlweCt profiled = server.make_query_profiled(client.get_client_id(),
                                               profiled_query, &profile);
  require_test(plain.ntt_form == profiled.ntt_form, "profiled form mismatch");
  require_test(plain.c0 == profiled.c0, "profiled c0 mismatch");
  require_test(plain.c1 == profiled.c1, "profiled c1 mismatch");
  require_test(profile.total() > std::chrono::nanoseconds::zero(),
               "profile total must be positive");
  require_test(profile.first_dim_core > std::chrono::nanoseconds::zero(),
               "first-dimension core was not measured");
  require_test(profile.expand > std::chrono::nanoseconds::zero() &&
                   profile.convert > std::chrono::nanoseconds::zero() &&
                   profile.other_dim > std::chrono::nanoseconds::zero(),
               "expand/convert/other-dim stages were not measured");
  // The stage sum is the whole call: no stage is double counted or skipped.
  const PirPipelineProfile zero;
  require_test(profile.first_dim_finalize > zero.first_dim_finalize,
               "first-dimension finalize was not measured");
  // Decrypting the profiled response recovers the requested plaintext.
  const RlwePt decrypted = client.decrypt_mod_q(profiled);
  RlwePt expected;
  source(29, expected);
  require_test(utils::plaintext_is_equal(decrypted, expected),
               "profiled response does not decrypt to the requested record");
  using Ms = std::chrono::duration<double, std::milli>;
  const double expand_ms = Ms(profile.expand).count();
  const double core_ms = Ms(profile.first_dim_core).count();
  const double total_ms = Ms(profile.total()).count();
  BENCH_PRINT("pir_profile: expand " << expand_ms << " ms, core " << core_ms
              << " ms, total " << total_ms << " ms");
}
