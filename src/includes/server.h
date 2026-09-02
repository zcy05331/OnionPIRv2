#pragma once

#include "gsw.h"
#include "pir.h"
#include "bv_keyswitch.h"
#include "pir_session.h"
#include "aligned_allocator.h"
#include "pir_profile.h"
#include <functional>
#include <map>
#include <sstream>
#include <unordered_map>

using PlaintextSource = std::function<void(size_t logical_index, RlwePt &out)>;

class PirServer {
public:
  PirServer(const PirParams &pir_params);
  ~PirServer();

  /**
   * Generate random data for the server database and directly set the database.
   * It pushes the data to the database in chunks.
   */
  void gen_data(const std::vector<size_t>& record_indices = {});

  // Stream logical plaintexts through the existing NTT/transpose database
  // preprocessing path. The rounded tail [logical_num_pt, num_pt_) is zero.
  void load_data(size_t logical_num_pt, const PlaintextSource &source,
                 const std::vector<size_t> &record_indices = {});

  // 服务端侧的 Algorithm 4 executable skeleton。输入是 QueryPack 生成的
  // full-q BFV packed query；输出是一条 coefficient-form ciphertext，已经完成
  // first-dim evaluation、高维 MUX reduction，以及最终 ModSwitch 到 small-q。
  // 其中 key setup 和 response serialization 位于本函数边界之外。
  RlweCt make_query(const size_t client_id, RlweCt &query);
  // Same pipeline, same operation order, same result as make_query; when
  // profile is non-null every stage's wall time is accumulated into it.
  RlweCt make_query_profiled(const size_t client_id, RlweCt &query,
                             PirPipelineProfile *profile);

  // [公共 Algorithm 2 入口] ExpandBFV：把一条系数形式全 q 打包查询按本服务器布局
  // 解包成 useful-leaf 常数（fst_dim_sz + L_EP·num_other_dims 片叶，容量
  // 2^expansion_height）。输入密文只读。需要 RGSW selector 的调用方对返回的
  // gadget 行自行跑补全（tree PIR：unpack_tree_query）；make_query 仍直接走内部路径。
  std::vector<RlweCt> expand_query(size_t client_id, RlweCt &query) const;

  // [Algorithm 3 补全] 作用在 expand_query 输出上：selector i（0 基）的 top 行位于
  // [fst_dim_sz + i·L_EP, fst_dim_sz + (i+1)·L_EP)，用该 client 注册的 RGSW(s) 密钥
  // 补全成完整 RGSW。展开行布局约定的单一来源：make_query 与树 unpack 路径都调用
  // 这一份实现，两者不可能漂移。非 const：补全复用本服务器的 GSWEval 转换状态。
  std::vector<GSWCt> complete_selectors(size_t client_id,
                                        const std::vector<RlweCt> &expanded);

  // Read-only view of the layout this server was constructed on, so external
  // composers (tree PIR unpack) can reject a shape-mismatched server before
  // doing any homomorphic work.
  inline const PirParams &get_params() const { return pir_params_; }

  // [Tree PIR M5] 对外部组装的响应做最终同环模数切换：与 make_query 完全一致地把
  // 全 q 密文居中重缩放到单 limb small-q，守卫同为 SmallQWidth。返回 true 表示已
  // 切换；false 表示该配置下响应保持全 q、密文未动。必须在全部同态运算之后调用。
  bool switch_response_to_small_q(RlweCt &response);

  // 只序列化 small-q response ciphertext：先 c0 后 c1，每个 coefficient
  // 固定写 small_q_width bits，bit order 为 LSB-first。这个 research prototype
  // format 无 authentication/integrity；对应 reader side 不检查 payload 后
  // trailing bytes/padding。
  size_t save_resp_to_stream(const RlweCt &response, std::stringstream &resp_stream);
  void set_client_bv_galois_key(const size_t client_id, bvks::BvGaloisKeys bv_keys);
  void set_client_gsw_key(const size_t client_id, GSWCt gsw_key);
  // Multi-layout API: retain shared immutable helper material instead of
  // copying it into every level server. Legacy setters remain supported.
  void set_client_session_keys(size_t client_id, SharedPirSessionKeys keys);
  SharedPirSessionKeys client_session_keys(size_t client_id) const;

  /**
  Asking the server to return the original plaintext (before NTT transformation) at the given index.
  This is not doing PIR. So this reveals the index to the server. This is
  only for testing purposes.
  */
  RlwePt direct_get_original_plaintext(const size_t index) const;


  // 对应 Algorithm 4 lines 4-6：在 plaintext database rows 与 first-dim encrypted
  // one-hot vector 之间做 homomorphic matrix-vector multiplication。输入
  // selection_vector 保持 coefficient form；输出 candidates 是按剩余维度索引的
  // coefficient-form BFV ciphertexts。
  std::vector<RlweCt> evaluate_first_dim(std::vector<RlweCt> &selection_vector,
                                         PirPipelineProfile *profile = nullptr);

  /**
   * @brief 处理 Algorithm 4 lines 7-14，用于 remaining dimensions。
   *
   * 其中 intermediate_db 起始为 first dimension 之后的 Nrest encrypted candidates。
   * 每个 RGSW selector bit 通过 ext_prod_mux 配对前/后半 candidates，消耗一层
   * 对应 tree layer。deepest level 可能是 ragged：只合并真实有 sibling 的 leaves，
   * 未配对 candidate 原位保留。输出是 high-dimensional binary index 选中的
   * 单个 encrypted candidate。
   */
  RlweCt evaluate_other_dim(std::vector<RlweCt> &intermediate_db, std::vector<GSWCt> &selectors);

  // 这里是 Homomorphic MUX：select(b, x_orig, y_orig) = x_orig + b*(y_orig-x_orig)。
  // b=0 保留原始 x，b=1 选择原始 y。实现有意复用 aliasing scratch：参数 y
  // 会先被改成 y-x，再作为 external product output 复用，最后加回 x。
  void ext_prod_mux(RlweCt &x, RlweCt &y, GSWCt &selection_cipher, RlweCt &result);


  friend class PirTest;

private:
  size_t num_pt_;
  std::map<size_t, bvks::BvGaloisKeys> client_bv_galois_keys_;
  std::map<size_t, GSWCt> client_gsw_keys_;
  std::map<size_t, SharedPirSessionKeys> client_sessions_;
  std::unordered_map<size_t, RlwePt> recorded_pts_; // pre-NTT plaintexts for test verification
  std::unique_ptr<db_coeff_t[], AlignedDeleter<db_coeff_t>> db_aligned_; // aligned database for fast first dim
  std::vector<inter_coeff_t> inter_res_; // intermediate result vector for fst dim

  // Composite-mod first-dim path (q = q1 * q2). When DBConsts::CompositeFirstDim
  // is true these replace db_aligned_ + inter_res_: the DB is split into two
  // u32 arrays (one per RNS limb), and the matmul writes into two u64 buffers
  // which are CRT-composed in inter_to_cts_composite.
  std::unique_ptr<uint32_t[], AlignedDeleter<uint32_t>> db_lo_;
  std::unique_ptr<uint32_t[], AlignedDeleter<uint32_t>> db_hi_;
  std::vector<uint64_t> inter_res_lo_;
  std::vector<uint64_t> inter_res_hi_;
  PirParams pir_params_;
  GSWEval key_gsw_;
  GSWEval data_gsw_;

  // Algorithm 2 ExpandBFV for packed query。输入是 coefficient-form、K-limb、
  // full-q 的 BFV ciphertext；client 已按 BitRev 把 plaintext slots 写入。
  // expansion 用 1-based binary heap 表示：每个 internal node 做一次
  // automorphism + BV key switch（Algorithm 2 Subs），再用 add/sub 和
  // negacyclic shift 生成两个 children。这里只 materialize 前
  // u = N0 + L_EP * (d - 1) 个 leaves；right-of-u subtrees 会被跳过，因为
  // 它们只会展开对 first-dim BFV 和后续 RGSW selector rows 都无用的 zero。
  std::vector<RlweCt> fast_expand_qry(size_t client_id, RlweCt &ciphertext) const;

  std::vector<RlweCt> full_expand_qry(size_t client_id, RlweCt &ciphertext) const;

  // Convert the first-dim matmul output `inter_res` into per-ciphertext form.
  // Two responsibilities:
  //   1. Layout transpose. mat_mat writes coeff-major:
  //        inter_res[level][i][p]   for i ∈ [0, other_dim_sz), p ∈ {0,1}
  //      with stride `other_dim_sz * 2` between coefficient levels. The
  //      per-ciphertext layout we want is poly-contiguous:
  //        cts[i].c{p}[level]
  //   2. NTT inverse on each polynomial (database is in NTT form).
  //
  // Assumes mat_mat already produced values < q at every output position
  // (chunked / AVX-512 paths both reduce per output write), so no `% q`
  // is performed here.
  void inter_to_cts(std::vector<RlweCt> &result, const inter_coeff_t *__restrict inter_res);

  // Fill the intermediate_db_ with some ciphertext. We just need to allocate the memory.
  void fill_inter_res();

  void prep_query(std::vector<RlweCt> &fst_dim_query, std::vector<db_coeff_t>& query_data);

  // Composite-mod variant: splits each NTT query coefficient into (mod q1,
  // mod q2) u32 buffers. Inputs are already NTT-transformed under q = q1*q2.
  void prep_query_composite(const std::vector<RlweCt> &fst_dim_query,
                            uint32_t *query_lo, uint32_t *query_hi);

  // Composite-mod variant of inter_to_cts: reads two per-limb u64 buffers,
  // CRT-composes each coefficient back to mod q = q1*q2, then runs a single
  // INTT mod q.
  void inter_to_cts_composite(std::vector<RlweCt> &result,
                              const uint64_t *inter_lo,
                              const uint64_t *inter_hi);

  // 对应 Algorithm 4 line 15：所有 homomorphic work 完成后，把 full-q response
  // centered-rescale 到一个 small-q limb，供 response codec 使用。提前 switch
  // 会损失 noise headroom，并与 full-q evaluation parameters 不匹配。
  void mod_switch_inplace(RlweCt &ciphertext, const uint64_t small_q);

};
