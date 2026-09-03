#include "tests.h"
#include "rlwe.h"

#include <sstream>

// decrypt_mod_q is the client's small-q response decoder: it always works
// under small_q, so its input must be a modulus-switched ciphertext. This
// test runs the exact response path a real query produces after the last
// homomorphic operation: encrypt under full q, switch to small_q, serialize
// with the wire codec, load, decode. A dense plaintext with both extreme
// values makes any rounding or codec truncation visible.
void PirTest::test_decrypt_mod_q() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirClient client(pir_params);
  PirServer server(pir_params);

  const size_t coeff_count = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const uint64_t t = pir_params.get_plain_mod();
  const uint64_t small_q = pir_params.get_small_q();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(0x6d6f6471ULL);

  std::vector<uint64_t> a(coeff_count, 0);
  for (size_t i = 0; i < coeff_count; ++i) a[i] = (7 * i + 1) % t;
  a[0] = 0;
  a[coeff_count - 1] = t - 1;

  RlweCt rlwe_ct;
  encrypt_bfv_rns(a, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, rlwe_ct);
  server.mod_switch_inplace(rlwe_ct, small_q);

  // Direct decode of the switched ciphertext.
  const RlwePt direct = client.decrypt_mod_q(rlwe_ct);
  require_test(direct.data == a,
               "decrypt_mod_q must recover every coefficient after the switch");

  // Wire round trip: the codec writes small_q_width bits per coefficient and
  // the loader must hand back the identical single-limb ciphertext.
  std::stringstream wire;
  const size_t bytes = server.save_resp_to_stream(rlwe_ct, wire);
  const size_t small_q_bits = std::bit_width(small_q - 1);
  require_test(bytes == utils::roundup_div(2 * coeff_count * small_q_bits,
                                           size_t{8}),
               "response codec byte count");
  const RlweCt loaded = client.load_resp_from_stream(wire);
  require_test(loaded.c0 == rlwe_ct.c0 && loaded.c1 == rlwe_ct.c1,
               "response codec round trip altered the ciphertext");
  const RlwePt decoded = client.decrypt_mod_q(loaded);
  require_test(decoded.data == a,
               "decrypt_mod_q must recover the plaintext from the wire form");
  BENCH_PRINT("decoded " << coeff_count << " coefficients from " << bytes
              << " wire bytes");
}
