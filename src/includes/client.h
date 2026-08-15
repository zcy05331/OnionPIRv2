#pragma once

#include "pir.h"
#include "gsw.h"
#include "bv_keyswitch.h"
#include "pir_session.h"
#include "rlwe.h"
#include <random>

class PirClient {
public:
  PirClient(const PirParams &pirparms);
  ~PirClient() = default;

  /**
  [2025 Algorithm 1: QueryPack]
  生成交给 fast_expand_qry/ExpandBFV 的 coefficient-form BFV 查询。
  pt_idx 会被拆成首维 one-hot 位置和后续 binary selectors；
  fast_generate_query 写入首维 BFV 部分，add_gsw_to_query 追加高维
  selectors 的 RGSW top rows。返回值仍在 full-q 下，服务端展开后恢复
  N0 + L_EP*(d-1) 个 constant ciphertexts。
  @param pt_idx The input to the PIR blackbox.
  */
  RlweCt fast_generate_query(const size_t pt_idx);
  RlweCt fast_generate_query(const PirParams &query_params, size_t pt_idx);

  // [2025 Algorithm 1: QueryPack]
  // fast_generate_query 的 helper：只把高维 binary selector bits 作为
  // RGSW top rows 打包进已经创建好的 BFV query。
  void add_gsw_to_query(RlweCt &query,
                        const std::vector<size_t> &query_indices);
  void add_gsw_to_query(const PirParams &query_params, RlweCt &query,
                        const std::vector<size_t> &query_indices);

  // Create custom BV-style Galois keys (no special prime).
  inline bvks::BvGaloisKeys create_bv_galois_keys() {
    return bvks::gen_bv_galois_keys(pir_params_, rlwe_sk_);
  }

  RlwePt decrypt_ct(const RlweCt &ct);
  // Produce the per-client GSW key (encryption of s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCt generate_gsw_from_key();
  SharedPirSessionKeys create_session_keys();

  inline size_t get_client_id() const { return client_id_; }

  // Debug/diagnostic first-limb phase/noise estimate. This is not K-aware and
  // is not SEAL-backed invariant_noise_budget.
  int noise_budget(const RlweCt &ct);


  // Fresh encryption of zero under the data modulus Q. Testing only:
  // used to measure the baseline initial noise budget without the
  // gadget-injection artifacts of fast_generate_query.
  RlweCt fresh_zero_ct();

  // 仅 response 的 PirServer::save_resp_to_stream inverse：先读 c0 再读 c1，
  // 每个 coefficient 固定 small_q_width bits，byte/field 内为 LSB-first。
  // 输出是 single-limb coefficient-form small-q ciphertext；prototype reader
  // 不做 authentication，也不验证 decoded coefficient < small_q，且不检查
  // expected payload 之后的额外 bytes（包括 padding）。decrypt path 后续按
  // small_q 取模/规约。
  RlweCt load_resp_from_stream(std::stringstream &resp_stream);

  // 解密 single-limb small-q response。ternary secret 会从旧 full-q first limb
  // 重新编码，使 -1 == old_q-1 变成 small_q-1；随后 phase = c0 + c1*s，
  // 再 round 回 plaintext mod t。
  RlwePt decrypt_mod_q(const RlweCt &ciphertext) const;


  friend class PirTest;

private:
  const size_t client_id_;
  PirParams pir_params_;
  std::mt19937_64 rng_;       // per-client PRNG for noise sampling
  RlweSk rlwe_sk_;            // ternary sk, NTT form under q

  // Algorithm 4 line 1 的 plaintext index 坐标映射：
  // return[0] 是首维 col_idx；其余 entries 是服务端归约顺序消费的
  // selector bits，第一个 bit 对应 deepest/ragged level。
  std::vector<size_t> get_query_indices(const PirParams &query_params,
                                        size_t pt_idx) const;

  // Populate sk_ntt_small_q_ by rewriting rlwe_sk_ from old_q to small_q
  // (ternary sk has -1 ≡ q-1; we need -1 ≡ small_q-1).
  std::vector<uint64_t> get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const;

};






