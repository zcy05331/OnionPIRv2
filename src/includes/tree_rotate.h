#pragma once

#include "server.h"
#include "tree_index.h"

#include <cstddef>
#include <span>

// Milestone-3 private negacyclic record rotation (blueprint sec. 12).
// "Rotation" here is exclusively coefficient monomial multiplication by X^e
// in Z_q[X]/(X^n + 1) — a negacyclic shift with sign changes — and never a
// BFV batching-slot rotation. Negative shifts are represented modulo 2n:
// X^{-k} = X^{2n-k}.

// Limb-wise addition of coefficient-form full-q ciphertexts, shared by the
// rotation, projection, and path-packing stages.
void tree_ct_add_inplace(RlweCt &acc, const RlweCt &x, const PirParams &scheme);

// Component-wise multiplication by X^{exponent} with exponent taken mod 2n.
// Coefficient form in, coefficient form out.
RlweCt mul_x_pow(const RlweCt &ct, size_t exponent_mod_2n,
                 const PirParams &scheme);

// Encrypted shift selector (sec. 12.2):
//   RotSelect(S, C, k) = C + ExtPdt(MulXPow(C, -k) - C, S),
// i.e. the ciphertext is multiplied by X^{-k} exactly when the RGSW bit S
// encrypts one. Composed from mul_x_pow and the repository CMux.
RlweCt rot_select(const RlweCt &ct, GSWCt &encrypted_bit, size_t shift,
                  PirServer &mux, const PirParams &scheme);

// Algorithm 5 PrivateRotateLevel: apply the level plan's gamma schedule so
// the plaintext is multiplied by X^{-gamma_l} and the target record moves to
// coefficient zero. The active selectors are gamma bits
// [gamma_begin, gamma_begin + gamma_count) with shift 2^{v - gamma_begin}
// for bit v — the full gamma at levels >= r and the high prefix above.
// `gamma_selectors` is the full r-length array indexed by global bit.
RlweCt private_rotate_level(RlweCt ct, const LevelPlan &plan,
                            std::span<GSWCt> gamma_selectors, PirServer &mux,
                            const PirParams &scheme);
