#include "tree_compress.h"

#include "utils.h"

#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_compress: ") + message);
  }
}

// Unsigned base-2^{base_log2} digit decomposition of every coefficient.
std::vector<std::vector<uint64_t>> decompose_poly(
    const std::vector<uint64_t> &poly, size_t base_log2, size_t l2) {
  std::vector<std::vector<uint64_t>> digits(
      l2, std::vector<uint64_t>(poly.size(), 0));
  const uint64_t mask = (base_log2 >= 64) ? ~uint64_t{0}
                                          : ((uint64_t{1} << base_log2) - 1);
  for (size_t i = 0; i < poly.size(); ++i) {
    uint64_t value = poly[i];
    for (size_t t = 0; t < l2; ++t) {
      digits[t][i] = value & mask;
      value >>= base_log2;
    }
  }
  return digits;
}

void add_inplace_mod(std::vector<uint64_t> &acc,
                     const std::vector<uint64_t> &x, uint64_t q) {
  for (size_t i = 0; i < acc.size(); ++i) {
    acc[i] = (acc[i] + x[i]) % q;
  }
}

}  // namespace

std::vector<uint64_t> small_ring_mul(const std::vector<uint64_t> &a,
                                     const std::vector<uint64_t> &b,
                                     uint64_t q) {
  const size_t n2 = a.size();
  require(b.size() == n2 && n2 > 0, "ring product needs equal-length inputs");
  // One uint128 reduction per output coefficient: every product is below
  // q^2 < 2^116 and at most n2 <= 2^11 of them accumulate per sign bucket,
  // so both buckets stay below 2^127.
  std::vector<uint64_t> out(n2, 0);
  for (size_t k = 0; k < n2; ++k) {
    uint128_t positive = 0, negative = 0;
    for (size_t i = 0; i < n2; ++i) {
      const uint64_t ai = a[i];
      if (ai == 0) continue;
      const size_t j = k >= i ? k - i : n2 + k - i;
      const uint64_t bj = b[j];
      if (bj == 0) continue;
      const uint128_t product = static_cast<uint128_t>(ai) * bj;
      if (k >= i) {
        positive += product;
      } else {
        negative += product;  // X^{i+j} with i + j = n2 + k wraps to -X^k
      }
    }
    const uint64_t pos = static_cast<uint64_t>(positive % q);
    const uint64_t neg = static_cast<uint64_t>(negative % q);
    out[k] = (pos + q - neg) % q;
  }
  return out;
}

CompressedPathResponse compress_path_response(
    const RlweCt &packed_full_q, const std::vector<size_t> &big_offsets,
    size_t level_count, const TreeRingSwitchKeys &keys,
    const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  require(scheme.K() == 1,
          "the d = 2 ring switch is implemented for single-limb schemes");
  require(!packed_full_q.ntt_form && packed_full_q.c0.size() == N &&
              packed_full_q.c1.size() == N,
          "compression consumes the coefficient-form full-q response");
  require(keys.n2 * 2 == N, "keys must target n2 = n / 2");
  require(keys.rows.size() == 2 && keys.rows[0].size() == keys.l2 &&
              keys.rows[1].size() == keys.l2,
          "one gadget row set per secret component is required");
  for (size_t offset : big_offsets) {
    require(offset % 2 == 0,
            "compression needs the payload on even coefficients");
  }

  const size_t n2 = keys.n2;
  const uint64_t q = scheme.get_rns_mods()[0];

  // Even/odd split: c0_e carries the payload phase, (a_e, Y a_o) carry the
  // secret-dependent part.
  std::vector<uint64_t> c0_e(n2), a_e(n2), a_o(n2);
  for (size_t k = 0; k < n2; ++k) {
    c0_e[k] = packed_full_q.c0[2 * k];
    a_e[k] = packed_full_q.c1[2 * k];
    a_o[k] = packed_full_q.c1[2 * k + 1];
  }
  // Y * a_o in the negacyclic small ring.
  std::vector<uint64_t> ya_o(n2);
  ya_o[0] = a_o[n2 - 1] == 0 ? 0 : q - a_o[n2 - 1];
  for (size_t k = 1; k < n2; ++k) ya_o[k] = a_o[k - 1];

  // Gadget key switch at full q: out = (c0_e, 0) + sum digit * KSK.
  std::vector<uint64_t> out_c0 = c0_e, out_c1(n2, 0);
  const std::vector<uint64_t> *components[2] = {&a_e, &ya_o};
  for (size_t c = 0; c < 2; ++c) {
    const auto digits =
        decompose_poly(*components[c], keys.base_log2, keys.l2);
    for (size_t t = 0; t < keys.l2; ++t) {
      add_inplace_mod(out_c0,
                      small_ring_mul(digits[t], keys.rows[c][t].first, q), q);
      add_inplace_mod(out_c1,
                      small_ring_mul(digits[t], keys.rows[c][t].second, q),
                      q);
    }
  }

  // Final centered rescale to the small response modulus (Milestone 5 for
  // the small ring): x -> round(x * q2 / q).
  const uint64_t q2 = scheme.get_small_q();
  require(q2 < q, "compression expects a narrower response modulus");
  const auto rescale = [&](std::vector<uint64_t> &poly) {
    for (uint64_t &x : poly) {
      x = static_cast<uint64_t>(
          (static_cast<uint128_t>(x) * q2 + q / 2) / q) % q2;
    }
  };
  rescale(out_c0);
  rescale(out_c1);

  CompressedPathResponse response;
  response.n2 = n2;
  response.c0 = std::move(out_c0);
  response.c1 = std::move(out_c1);
  response.modulus = q2;
  response.level_count = level_count;
  response.level_offsets.reserve(big_offsets.size());
  for (size_t offset : big_offsets) {
    response.level_offsets.push_back(offset / 2);
  }
  return response;
}

std::vector<std::vector<uint64_t>> decode_compressed_path(
    const CompressedPathResponse &response,
    const TreeRingSwitchSecret &secret, uint64_t plain_mod, size_t g,
    size_t rho) {
  const size_t n2 = response.n2;
  require(secret.n2 == n2 && secret.s2.size() == n2,
          "decoding secret does not match the response ring");
  require(response.level_offsets.size() == response.level_count,
          "compressed response is missing its offset map");
  require(rho % 2 == 0, "record stride must be even for the d = 2 switch");

  // Re-encode the ternary secret under the response modulus and decrypt:
  // phase = c0 + c1 * s2 (mod q2), message = round(phase * t / q2).
  const uint64_t q2 = response.modulus;
  std::vector<uint64_t> s2_q2(n2);
  for (size_t i = 0; i < n2; ++i) {
    s2_q2[i] = secret.s2[i] > 1 ? q2 - 1 : secret.s2[i];
  }
  std::vector<uint64_t> phase = small_ring_mul(response.c1, s2_q2, q2);
  for (size_t i = 0; i < n2; ++i) {
    phase[i] = (phase[i] + response.c0[i] % q2) % q2;
  }

  uint64_t max_noise = 0;
  std::vector<uint64_t> values(n2);
  for (size_t i = 0; i < n2; ++i) {
    const uint64_t m =
        utils::round_div_u128(static_cast<uint128_t>(phase[i]) * plain_mod,
                              q2) % plain_mod;
    values[i] = m;
    const uint64_t approx =
        utils::round_div_u128(static_cast<uint128_t>(q2) * m, plain_mod) % q2;
    const uint64_t up = phase[i] >= approx ? phase[i] - approx
                                           : q2 - approx + phase[i];
    const uint64_t noise = up > q2 / 2 ? q2 - up : up;
    if (noise > max_noise) max_noise = noise;
  }
  BENCH_PRINT("Compressed-response noise: max " << max_noise << " of bound "
              << q2 / (2 * plain_mod));

  const size_t rho2 = rho / 2;
  std::vector<std::vector<uint64_t>> path;
  path.reserve(response.level_count);
  for (size_t level = 0; level < response.level_count; ++level) {
    std::vector<uint64_t> chunks(g);
    for (size_t j = 0; j < g; ++j) {
      chunks[j] = values[response.level_offsets[level] + j * rho2];
    }
    path.push_back(std::move(chunks));
  }
  return path;
}
