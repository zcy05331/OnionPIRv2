#pragma once

#include "client.h"
#include "pir.h"
#include "server.h"
#include "tree_index.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// Packed tree query construction (blueprint sec. 8). The packed layout is
//   [ alpha one-hot: N0 slots ]
//   [ beta[0]: ell rows ] ... [ beta[b-1]: ell rows ]
//   [ gamma[0]: ell rows ] ... [ gamma[r-1]: ell rows ]
// with every logical slot j written at coefficient BitRev(j, h_q), so the
// existing ExpandBFV heap walk recovers slot j at expanded leaf j. Both
// gadget-row groups reuse the scheme's L_EP-length data gadget so the existing
// query_to_gsw completion path applies unchanged; the scheme binding below
// therefore freezes ell_beta = ell_gamma = scheme.get_l().
//
// Two distinct scales enter the packed ciphertext (sec. 8.2) and deliberately
// do NOT share a helper:
//   - the alpha one-hot is a BFV plaintext value, lifted by the full-Q Delta
//     with the W^-1 mod t pre-scale supplied by the caller;
//   - beta/gamma gadget rows are RLWE*-style constants with no Delta factor,
//     added per RNS limb with the W^-1 mod q_k pre-scale.

// Bind (L, a) to the active OnionPIRv2 scheme: n = PolyDegree,
// ell_beta = ell_gamma = scheme.get_l(), t and the RNS moduli from `scheme`,
// same-ring response. Throws on any blueprint sec. 3.2 violation.
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a,
                                              const PirParams &scheme);

// Expansion-only PirParams view for a tree query: fst_dim_sz = N0,
// num_other_dims = b + r, expansion_height = h_q. Built via
// PirParams::with_query_shape, so it is valid for fast_expand_qry and
// session-key checks but is NOT a database layout (see pir.h).
PirParams tree_query_expansion_params(const TreePirParams &tree,
                                      const PirParams &scheme);

// Add the full-Q BFV lift of `value_mod_t` (already including any W^-1 mod t
// pre-scale) to the message-dependent component at coefficient
// BitRev(logical_coeff, h_q). The ciphertext must be coefficient-form full-q.
void add_bfv_query_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            uint64_t value_mod_t);

// Semantic helper of blueprint sec. 8.3: add an RLWE*-style constant (one
// value per RNS limb, already including any W^-1 mod q_k pre-scale) to the
// message-dependent component at coefficient BitRev(logical_coeff, h_q). The
// helper owns the ciphertext-component convention: under the repository's
// (c0, c1) = (-as + e + Delta*m, a) layout it modifies c0. Callers must not
// hardcode that choice.
void add_rlwe_star_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            std::span<const uint64_t> value_per_limb);

// Algorithm 3 QueryGen: one packed tree query for `leaf` under the client's
// long-term secret, with fresh encryption randomness drawn from the client's
// RNG on every call. Composition follows sec. 8.5: encryption of zero, alpha
// one-hot BFV lift, then beta and gamma gadget rows appended — no second
// independent BFV/RLWE encoder. Only the returned ciphertext is
// query-dependent; no per-level value or oracle type is reachable from it.
RlweCt make_tree_query(PirClient &client, const PirParams &scheme,
                       const TreePirParams &tree, size_t leaf);

// Server-side unpack result (blueprint sec. 9.1/9.2). The first N0 expanded
// leaves stay BFV ciphertexts encrypting the alpha one-hot vector A^(0);
// every beta/gamma gadget-row group is completed into one RGSW selector with
// the client's registered RGSW(s) key. Selector order matches the packed
// layout: beta_selectors[u] = RGSW(beta_u), gamma_selectors[v] = RGSW(gamma_v).
struct ExpandedTreeQuery {
  std::vector<RlweCt> alpha;
  std::vector<GSWCt> beta_selectors;
  std::vector<GSWCt> gamma_selectors;
};

// Algorithm "QueryUnpack" (sec. 9): run the existing coefficient-expansion
// tree with useful-leaf pruning, keep the alpha range as BFV, and convert the
// selector groups to RGSW. `server` must have been constructed on
// tree_query_expansion_params(tree, scheme) and hold the client's session
// keys; a shape- or scheme-mismatched server is rejected before any
// homomorphic work. The packed query is only read.
ExpandedTreeQuery unpack_tree_query(const PirServer &server,
                                    const PirParams &scheme,
                                    const TreePirParams &tree,
                                    size_t client_id, RlweCt &query);
