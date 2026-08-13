#pragma once

#include "pir.h"
#include "gsw.h"
#include "bv_keyswitch.h"
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

  // [2025 Algorithm 1: QueryPack]
  // fast_generate_query 的 helper：只把高维 binary selector bits 作为
  // RGSW top rows 打包进已经创建好的 BFV query。
  void add_gsw_to_query(RlweCt &query, const std::vector<size_t> query_indices);

  // Create custom BV-style Galois keys (no special prime).
  inline bvks::BvGaloisKeys create_bv_galois_keys() {
    return bvks::gen_bv_galois_keys(pir_params_, rlwe_sk_);
  }

  RlwePt decrypt_ct(const RlweCt &ct);
  // Produce the per-client GSW key (encryption of s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCt generate_gsw_from_key();

  inline size_t get_client_id() const { return client_id_; }

  // Noise budget via a bridge to SEAL's invariant_noise_budget (debug/test only).
  int noise_budget(const RlweCt &ct);


  // Fresh encryption of zero under the data modulus Q. Testing only:
  // used to measure the baseline initial noise budget without the
  // gadget-injection artifacts of fast_generate_query.
  RlweCt fresh_zero_ct();

  // load the response from the stream and recover the ciphertext
  RlweCt load_resp_from_stream(std::stringstream &resp_stream);

  // Decrypt a single-mod RlweCt under small_q using our custom decryptor.
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
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // Populate sk_ntt_small_q_ by rewriting rlwe_sk_ from old_q to small_q
  // (ternary sk has -1 ≡ q-1; we need -1 ≡ small_q-1).
  std::vector<uint64_t> get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const;

};







