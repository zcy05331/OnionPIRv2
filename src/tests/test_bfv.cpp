#include "tests.h"
#include "rlwe.h"
#include "utils.h"
#include "hexl/hexl.hpp"
#include <random>

// BFV primitives on the native RLWE layer: encrypt, add (coefficient and NTT
// form), multiply a ciphertext by an NTT-form plaintext, decrypt. Every
// result is checked against the Z_t[x]/(x^N+1) arithmetic it must implement.
void PirTest::bfv_example() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q   = pir_params.get_rns_mods()[0];
  const uint64_t t   = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  BENCH_PRINT("N=" << N << "  q=" << q << "  t=" << t);

  std::mt19937_64 rng(0x626676ULL);
  RlweSk sk = gen_secret_key(N, q, rng);

  // ============== BFV + BFV addition (coefficient form) ==============
  std::vector<uint64_t> a(N, 0), b(N, 0);
  a[0] = 1; a[1] = 9;
  b[0] = 3; b[1] = 6;

  RlweCt ct_a, ct_b;
  encrypt_bfv(a, sk, N, q, t, sigma, rng, ct_a);
  encrypt_bfv(b, sk, N, q, t, sigma, rng, ct_b);

  {
    RlwePt pt;
    int budget = decrypt_and_budget(ct_a, sk, N, q, t, pt);
    BENCH_PRINT("Noise budget before add: " << budget << " bits");
    require_test(budget > 0, "fresh BFV ciphertext has no noise budget");
    require_test(pt.data == a, "fresh BFV ciphertext does not decrypt to a");
  }

  RlweCt ct_sum = ct_a;
  rlwe_add_inplace(ct_sum, ct_b, q);

  RlwePt pt_sum;
  int sum_budget = decrypt_and_budget(ct_sum, sk, N, q, t, pt_sum);
  BENCH_PRINT("Noise budget after add: " << sum_budget << " bits");
  for (size_t i = 0; i < N; ++i) {
    require_test(pt_sum.data[i] == (a[i] + b[i]) % t,
                 "BFV + BFV coefficient mismatch");
  }
  require_test(sum_budget > 0, "BFV addition exhausted the noise budget");
  PRINT_BAR;

  // ============== NTT-form add ==============
  // encrypt, transform, add, transform back, decrypt.
  RlweCt ct_a_ntt = ct_a;
  RlweCt ct_b_ntt = ct_b;
  rlwe_ntt_fwd_inplace(ct_a_ntt, q, N);
  rlwe_ntt_fwd_inplace(ct_b_ntt, q, N);
  RlweCt ct_ntt_sum = ct_a_ntt;
  rlwe_add_inplace(ct_ntt_sum, ct_b_ntt, q);
  rlwe_ntt_inv_inplace(ct_ntt_sum, q, N);

  RlwePt pt_ntt_sum;
  decrypt(ct_ntt_sum, sk, N, q, t, pt_ntt_sum);
  require_test(pt_ntt_sum.data == pt_sum.data,
               "NTT-form addition differs from coefficient-form addition");
  PRINT_BAR;

  // ============== Ciphertext × plaintext in NTT form ==============
  // This is the operation used in the first-dimension matrix-vector multiply.
  // ct in NTT form, scalar plaintext in NTT form. Pointwise multiply c0, c1.
  std::vector<uint64_t> scalar(N, 0);
  scalar[0] = 2;
  scalar[1] = 3;

  std::vector<uint64_t> scalar_ntt = scalar;
  utils::ntt_fwd(scalar_ntt.data(), N, q);

  RlweCt ct_a_for_mul = ct_a;
  rlwe_ntt_fwd_inplace(ct_a_for_mul, q, N);

  RlweCt ct_mul = ct_a_for_mul;
  intel::hexl::EltwiseMultMod(ct_mul.c0.data(), ct_a_for_mul.c0.data(),
                              scalar_ntt.data(), N, q, 1);
  intel::hexl::EltwiseMultMod(ct_mul.c1.data(), ct_a_for_mul.c1.data(),
                              scalar_ntt.data(), N, q, 1);
  rlwe_ntt_inv_inplace(ct_mul, q, N);

  RlwePt pt_mul;
  int mul_budget = decrypt_and_budget(ct_mul, sk, N, q, t, pt_mul);
  // Negacyclic product a * scalar in Z_t[x]/(x^N+1); both operands live in
  // degrees 0..1 so no wrap-around term appears.
  std::vector<uint64_t> expected(N, 0);
  for (size_t i = 0; i < N; ++i) {
    if (a[i] == 0) continue;
    for (size_t j = 0; j < N; ++j) {
      if (scalar[j] == 0) continue;
      const uint64_t term = (a[i] * scalar[j]) % t;
      if (i + j < N) {
        expected[i + j] = (expected[i + j] + term) % t;
      } else {
        expected[i + j - N] = (expected[i + j - N] + t - term) % t;
      }
    }
  }
  require_test(pt_mul.data == expected,
               "ciphertext x NTT plaintext differs from the ring product");
  BENCH_PRINT("Noise budget after scalar mult: " << mul_budget << " bits");
  require_test(mul_budget > 0, "plaintext multiplication exhausted the budget");
}
