#pragma once

#include "bv_keyswitch.h"
#include "pir.h"
#include "rlwe.h"

#include <cstddef>

// Milestone-3 one-sided coefficient projection (blueprint sec. 13). The map
//   pi_d(sum f_e X^e) = sum_{2^d | e} f_e X^e
// is realized by the recurrence 2*pi_{u+1}(f) = pi_u(f) + tau_{eta_u}(pi_u(f))
// with eta_u = n/2^u + 1, so d substitution/key-switch rounds double the kept
// coefficients d times; pre-scaling the ciphertext by 2^{-d} cancels that
// growth exactly. The automorphism sum projects the noise term the same way,
// so projection adds only key-switch noise on top of |e|.
//
// Algorithm 6 ProjectRecord: pre-scale both components by 2^{-depth} per RNS
// limb, then for j = 0..depth-1 add Subs(T, eta_j) into T. The Galois keys
// must cover eta_j = (n >> j) + 1 for every j < depth — i.e. a bundle
// generated at height >= depth (log2(n) covers every legal projection).
// Coefficient form in, coefficient form out. After a correct private
// rotation, depth = min(r, level) leaves the target value in coefficient
// zero and zero everywhere else (sec. 13.2).
RlweCt project_keep_stride(RlweCt ct, size_t depth,
                           const bvks::BvGaloisKeys &keys,
                           const PirParams &scheme);
