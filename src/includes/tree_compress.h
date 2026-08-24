#pragma once

#include "pir.h"
#include "rlwe.h"

#include <cstddef>
#include <cstdint>
#include <vector>

// Milestone-7 small-ring response compression (blueprint sec. 23.3) for the
// d = n / n2 = 2 ring switch, plus the alignment half of sec. 23.4: the
// packer places every path slot on the even-coefficient sublattice so the
// whole payload survives the compression map.
//
// Construction. Split f(X) = f_e(X^2) + X f_o(X^2) with f_e, f_o in
// R_{n2} = Z_q[Y]/(Y^{n2} + 1) (Y = X^2; Y^{n2} = X^n = -1 keeps the small
// ring negacyclic). The even part of the big phase c0 + c1 s is
//   c0_e + a_e s_e + Y a_o s_o,
// an MLWE-style ciphertext under the two small-ring components of the big
// secret. The client registers one independent target secret s2 and gadget
// key-switch rows KSK_c[t] = RLWE_{n2,q}(B^t s_c) under s2 for c in {e, o};
// the server decomposes a_e and Y a_o into base-B digits and accumulates
// digit * KSK to obtain one R_{n2} ciphertext under s2 with the same
// payload.
//
// Error analysis (k1_comp, q ~ 2^58, B = 2^29, l2 = 2, n2 = 1024). The
// switch runs at full q where Delta = q/t ~ 2^45:
//   e_out = e_big + sum_{c,t} digit_{c,t} * e_ksk[c,t]
// with |digit| < B, so the key-switch term is bounded by roughly
// d * l2 * B * |e_fresh| * sqrt(n2) ~ 2^39, far below Delta/2 ~ 2^44. The
// final centered rescale to the 22-bit small q scales everything by
// q2/q ~ 2^-36: the carried path noise (~2^42.6) returns to its usual ~100,
// the key-switch term shrinks to O(10), and rounding adds ~|s2|/2 — the
// same decoding margin as the uncompressed response, measured in the test.
//
// The small-ring products use a coefficient-domain negacyclic schoolbook
// with one uint128 reduction per output (n2 * q^2 < 2^127), so no NTT root
// registration is needed for the composite modulus; a prime-modulus NTT
// path is a later optimization.

struct TreeRingSwitchKeys {
  size_t n2 = 0;
  size_t base_log2 = 0;
  size_t l2 = 0;
  // rows[c][t] = (c0, c1) over R_{n2} at full q encrypting B^t * s_c under
  // s2, c = 0 for the even component, 1 for the odd one.
  std::vector<std::vector<std::pair<std::vector<uint64_t>,
                                    std::vector<uint64_t>>>> rows;
};

// Client-held decoding secret for the compressed response.
struct TreeRingSwitchSecret {
  size_t n2 = 0;
  std::vector<uint64_t> s2;  // ternary, coefficient form mod full q
};

struct TreeRingSwitchBundle {
  TreeRingSwitchKeys keys;     // registered with the server
  TreeRingSwitchSecret secret; // stays with the client
};

// One compressed path response: a single R_{n2} ciphertext. Offsets are the
// big-ring level offsets divided by d = 2; level slot z's chunk j sits at
// coefficient z + j * (rho / 2).
struct CompressedPathResponse {
  size_t n2 = 0;
  std::vector<uint64_t> c0, c1;  // coefficient form
  uint64_t modulus = 0;          // small q after the final rescale
  size_t level_count = 0;
  std::vector<size_t> level_offsets;  // small-ring offsets per level
};

// Negacyclic product in R_{n2} mod q (schoolbook reference kernel).
std::vector<uint64_t> small_ring_mul(const std::vector<uint64_t> &a,
                                     const std::vector<uint64_t> &b,
                                     uint64_t q);

// Server side: take the *pre-modulus-switch* packed big-ring response whose
// payload lies entirely on even coefficients, ring-switch it to R_{n2}
// under the registered keys at full q, then centered-rescale to the small
// modulus. `big_offsets` are the packer's per-level offsets (all even).
CompressedPathResponse compress_path_response(
    const RlweCt &packed_full_q, const std::vector<size_t> &big_offsets,
    size_t level_count, const TreeRingSwitchKeys &keys,
    const PirParams &scheme);

// Client side: decrypt under s2 and read g chunks per level at stride
// rho / 2.
std::vector<std::vector<uint64_t>> decode_compressed_path(
    const CompressedPathResponse &response,
    const TreeRingSwitchSecret &secret, uint64_t plain_mod, size_t g,
    size_t rho);
