#include "tests.h"
#include "rlwe.h"

// Homomorphic MUX: select(b, x, y) = x + b * (y - x). RGSW(1) must return y
// and RGSW(0) must return x, coefficient for coefficient.
void PirTest::test_ext_prod_mux() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const RnsTables &tables = pir_params.get_rns_tables();
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(0x1234ULL);

  // Dense payloads so a wrong pairing or a dropped coefficient is visible.
  std::vector<uint64_t> a(coeff_count, 0), b(coeff_count, 0);
  for (size_t i = 0; i < coeff_count; ++i) {
    a[i] = (5 * i + 7) % t;
    b[i] = (3 * i + 9) % t;
  }

  GSWEval data_gsw(pir_params, pir_params.get_l(), pir_params.get_base_log2());
  std::vector<uint64_t> one(coeff_count, 0); one[0] = 1;
  std::vector<uint64_t> zero(coeff_count, 0);
  GSWCt one_gsw = data_gsw.plain_to_gsw(one, client.rlwe_sk_, rng);
  GSWCt zero_gsw = data_gsw.plain_to_gsw(zero, client.rlwe_sk_, rng);

  const auto mux = [&](GSWCt &selector) {
    // ext_prod_mux consumes its second operand as scratch: encrypt fresh.
    RlweCt a_ct, b_ct;
    encrypt_bfv_rns(a, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, a_ct);
    encrypt_bfv_rns(b, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, b_ct);
    RlweCt result;
    result.c0.assign(coeff_count * qs.size(), 0);
    result.c1.assign(coeff_count * qs.size(), 0);
    server.ext_prod_mux(a_ct, b_ct, selector, result);
    RlwePt pt;
    decrypt_rns(result, client.rlwe_sk_, coeff_count, qs, t, tables, pt);
    return pt;
  };

  const RlwePt picked_b = mux(one_gsw);
  require_test(picked_b.data == b, "mux(RGSW(1), a, b) must decrypt to b");
  const RlwePt picked_a = mux(zero_gsw);
  require_test(picked_a.data == a, "mux(RGSW(0), a, b) must decrypt to a");
  BENCH_PRINT("K=" << qs.size() << " mux(RGSW(1)) = b and mux(RGSW(0)) = a on "
              << coeff_count << " coefficients");
  PRINT_BAR;
}
