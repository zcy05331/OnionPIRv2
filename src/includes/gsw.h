#pragma once
#include "pir.h"
#include "rlwe.h"
#include <random>
#include <vector>


// [RGSW flat layout] GSWCt 是 external_product 消费的扁平 2*l x 2
// polynomial matrix。外层 vector 有 2*l rows；每个 row 是
//   [c0 的 K*N values][c1 的 K*N values]
// 因而 row.size() == 2*K*N。每个 polynomial 内部沿用 RlweCt 的
// limb-major layout: [q0 的 N coefficients][q1 的 N coefficients]...
// external_product 会把输入 BFV/RLWE 的 c0、c1 分解成 2*l digit rows，
// 作为 [1 x 2*l] 向量乘上这个 [2*l x 2] RGSW matrix，输出一个 BFV/RLWE
// ciphertext。GSWCt rows 通常预先在 NTT domain；分解 rows 会在乘法前转 NTT。
typedef std::vector<std::vector<uint64_t>> GSWCt;

class GSWEval {
  private:
    PirParams pir_params_;
    size_t l_;
    size_t base_log2_;

    // Reusable scratch for external_product, sized once then reused across the
    // many calls (avoids per-call heap churn). ep_decomp_: 2*l_ decomposed rows,
    // each K*N, matching the [c0 digits][c1 digits] side of the RGSW layout.
    // ep_tmp_: one N-block for the matmul. Mirrors bv_keyswitch's
    // GaloisScratch; the GSWEval object is intended for the repository's
    // single-threaded evaluation path because this scratch is mutated per call.
    std::vector<std::vector<uint64_t>> ep_decomp_;
    std::vector<uint64_t> ep_tmp_;
    std::vector<int64_t> ep_dwork_;  // centered working values for vectorized decomp

  public:
    GSWEval(const PirParams &pir_params, const size_t l, const size_t base_log2)
        : pir_params_(pir_params), l_(l), base_log2_(base_log2) {}
    ~GSWEval() = default;
    GSWEval(const GSWEval &gsw_eval) = default;

    /*!
      Computes the external product between a RGSW ciphertext and a BFV/RLWE
      ciphertext. The BFV input is decomposed internally into 2*l rows; gsw_enc
      must already be the matching flat 2*l x 2 matrix described above.
      @param gsw_enc - RGSW ciphertext matrix in NTT form; selector ciphertexts
                       should encrypt 0 or 1 to prevent large noise growth.
      @param bfv - raw BFV/RLWE input ciphertext in coefficient form; this
                   function performs the gadget decomposition internally.
      @param res_ct - output BFV/RLWE ciphertext, left in NTT form.
    */
    void external_product(GSWCt const &gsw_enc, RlweCt const &bfv,
                          RlweCt &res_ct,
                          LogContext context = LogContext::GENERIC);

    /*!
      MP-gadget decomposition (K>=2). Composes the per-coefficient RNS values
      to a multi-precision integer, extracts unsigned base-B digits, then
      decomposes back to RNS. Emits 2 * l_ rows; row p (MSB-first within each
      half) holds the digit at exponent l_-1-p.
      @param ct - input BFV ciphertext (coefficient form, K-limb).
      @param output - decomposed rows, each K*N uint64 in limb-major layout.
    */
    void decomp_rlwe_mp(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                        LogContext context = LogContext::GENERIC);

    // Similar to decomp_rlwe_mp. Use this when rn_mod_cnt = 1. Skips the
    // RNS<->MP conversions; signed-digit decomposition directly under q.
    void decomp_rlwe_single_mod(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                                   LogContext context = LogContext::GENERIC);

    // Transform decomposed coefficients to NTT form
    void decomp_to_ntt(std::vector<std::vector<uint64_t>> &decomp_coeffs,
                      LogContext context = LogContext::GENERIC);

    /*!
      Generates a GSW ciphertext from a BFV ciphertext query.

      @param query - query.size() top-half BFV ciphertext rows (L_EP rows in the
                     data-selector path); output is resized to 2*query.size()
                     RGSW rows after completion.
      @param gsw_key - RGSW encryption of s
      @param output - output to store the GSW ciphertext as a vector of vectors of
      polynomial coefficients
    */
    void query_to_gsw(std::vector<RlweCt> query, GSWCt gsw_key,
                      GSWCt &output);

    /*!
      Encrypt a plaintext polynomial as a full RGSW ciphertext in NTT form.
      Produces the flat layout consumed by external_product: 2*l_ rows, each row
      = [c0 K*N values][c1 K*N values]. Each q_k limb is in NTT form.
      @param plaintext - polynomial of length N, interpreted under q_0 and
                         re-canonicalised per q_k when K > 1.
      @param sk        - NTT-form ternary secret key.
      @param rng       - randomness source for a, e.
    */
    GSWCt plain_to_gsw(std::vector<uint64_t> const &plaintext,
                               const RlweSk &sk, std::mt19937_64 &rng);

    // Transform the given GSWCipher text from polynomial representation to NTT representation.
    void gsw_ntt_forward(GSWCt &gsw);
};