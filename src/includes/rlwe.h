#pragma once
#include <cstdint>
#include <random>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal RLWE types replacing seal::Ciphertext / seal::SecretKey / seal::Plaintext.
// [核心布局] 这些类型都把 polynomial 存为 flat uint64_t buffer；带 RNS
// limbs 的类型在各自结构注释中说明 limb-major layout 和 domain invariant。
// ---------------------------------------------------------------------------

// [核心布局] 一个 RLWE/BFV ciphertext 由 c0、c1 两个 polynomial 组成。
// 每个 polynomial 使用 limb-major 存储：
//   [q0 的 N 个 coefficients][q1 的 N 个 coefficients]...
// 不是按 coefficient 交错。ntt_form 只记录当前 domain，不会触发转换；
// 调用者必须显式执行 NTT/INTT，并保持标记与真实 buffer 一致。
struct RlweCt {
    std::vector<uint64_t> c0; // first polynomial (size = N * K)
    std::vector<uint64_t> c1; // second polynomial (size = N * K)
    bool ntt_form = false;

    uint64_t       *data(size_t i)       { return i == 0 ? c0.data() : c1.data(); }
    const uint64_t *data(size_t i) const { return i == 0 ? c0.data() : c1.data(); }
    bool &is_ntt_form() { return ntt_form; }

    // Resize both polynomials to n elements (n = N * K).
    void resize(size_t n) { c0.assign(n, 0); c1.assign(n, 0); }

    // Number of elements per polynomial (0 if not yet allocated).
    size_t poly_size() const { return c0.size(); }
};

// [核心布局] RlweSk 是一个 ternary secret polynomial，不含 c0/c1。
// data 使用 limb-major 存储：
//   [q0 的 N 个 coefficients][q1 的 N 个 coefficients]...
// 不是按 coefficient 交错。secret key 生成后按 limb 进入 NTT domain；
// 调用者必须保持 data 的真实 domain 与使用位置一致。
struct RlweSk {
    std::vector<uint64_t> data;
    size_t poly_size() const { return data.size(); }
};

// [核心布局] RlwePt 是一个 plaintext polynomial，不含 c0/c1。
// 当前 BFV plaintext data 只有 N 个 coefficients，取值在 [0, t)，不带 RNS
// limbs，也不由 ntt_form 标记管理。
struct RlwePt {
    std::vector<uint64_t> data;
    size_t coeff_count() const { return data.size(); }
};

// ---------------------------------------------------------------------------
// Single-modulus RLWE encryption primitives.
// All functions operate on a single prime q (K == 1).
// Secret keys are always stored in NTT form.
// ---------------------------------------------------------------------------

// Sample a fresh ternary secret key and convert it to NTT form.
RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng);

// Symmetric encryption of zero under secret key sk:
//   c1 = a  (uniform in [0, q))
//   c0 = -(a*s + e) mod q   where e ~ N(0, sigma²)
// encrypt_zero 中 m=0，只生成 c0=-(a*s+e)、c1=a；encrypt_bfv 随后才把
// Delta*m 加到 c0，因此解密 phase=c0+c1*s。
// error 的符号与常见 BFV 记法可能相反，但分布对称，解密语义等价。
// If ntt_form == true, both c0 and c1 are returned in NTT form; otherwise
// both are in coefficient form.
void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form = false);

// BFV symmetric encryption of a message polynomial `m` (length N, values < t):
//   c = Enc(0) + (Δ·m, 0)   where Δ = ⌊q/t⌋.
// 本实现采用 c0=-(a*s+e)+Delta*m、c1=a，因此解密 phase=c0+c1*s。
// error 的符号与常见 BFV 记法可能相反，但分布对称，解密语义等价。
// Encrypts in coefficient form (matches seal::Encryptor::encrypt_symmetric for
// a non-NTT input plaintext).
void encrypt_bfv(const std::vector<uint64_t> &m, const RlweSk &sk,
                 size_t N, uint64_t q, uint64_t t, double sigma,
                 std::mt19937_64 &rng, RlweCt &ct);

// Decrypt a single-modulus ciphertext into a plaintext polynomial modulo t.
//   phase[i] = (c0 + c1 * s)[i]          in [0, q)
//   pt[i]    = round(phase[i] * t / q)   mod t
// 这与 c0=-(a*s+e)+Delta*m、c1=a 的加密约定配套；error 符号和常见 BFV
// 记法可能相反，但 phase 中 Delta*m-e 的解密语义等价。
// ct may be in either NTT or coefficient form (determined by ct.ntt_form).
void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q,
             uint64_t t, RlwePt &pt);

// Decrypt and also return the invariant noise budget in bits.
// Equivalent to SEAL's Decryptor::invariant_noise_budget + decrypt().
int decrypt_and_budget(const RlweCt &ct, const RlweSk &sk, size_t N,
                       uint64_t q, uint64_t t, RlwePt &pt);

// ---------------------------------------------------------------------------
// RlweCt arithmetic (single-modulus). All operands must be the same NTT form;
// caller upholds the invariant (no runtime check on the hot path).
// ---------------------------------------------------------------------------

void rlwe_add_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_sub_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_add(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);
void rlwe_sub(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);

// NTT forward/inverse on both polynomials. Updates ct.ntt_form.
void rlwe_ntt_fwd_inplace(RlweCt &ct, uint64_t q, size_t N);
void rlwe_ntt_inv_inplace(RlweCt &ct, uint64_t q, size_t N);

// Negacyclic shift by `index` of each polynomial (coefficient form only).
// dst may alias src.
void rlwe_shift(const RlweCt &src, RlweCt &dst, size_t index, uint64_t q, size_t N);

// ---------------------------------------------------------------------------
// K-limb (RNS) RLWE primitives.
// All functions operate on K = qs.size() limbs concatenated in mod0 || mod1 || ...
// order. The single-modulus helpers above are the K=1 specialisation.
// Currently supports K = 1 or K = 2 (matching compose_rns_to_mp's range).
// ---------------------------------------------------------------------------

struct RnsTables;  // defined in pir.h; only K=2 fields are used here

// One ternary polynomial reduced and NTT'd per limb. data layout: limb k at
// offset k*N. The same ternary coefficients are used across all limbs.
RlweSk gen_secret_key_rns(size_t N, const std::vector<uint64_t> &qs,
                          std::mt19937_64 &rng);

// Encryption of zero under sk:
//   c1_k = a_k                     (uniform in [0, q_k))
//   c0_k = -(a_k*sk_k + e_k) mod q_k  with shared signed Gaussian e
// encrypt_zero_rns 中 m=0，只生成 c0=-(a*s+e)、c1=a；encrypt_bfv_rns
// 随后才把 Delta*m 加到 c0，因此解密 phase=c0+c1*s。
// error 的符号与常见 BFV 记法可能相反，但分布对称，解密语义等价。
void encrypt_zero_rns(const RlweSk &sk, size_t N,
                      const std::vector<uint64_t> &qs,
                      double sigma, std::mt19937_64 &rng,
                      RlweCt &ct, bool ntt_form = false);

// BFV encryption: encrypt_zero + add round(Q*m[i]/t) to c0[i]。
// Delta≈Q/t；K=2 时必须先在 composite Q 上形成一致的 scale，再把
// 同一个整数表示投影到每个 RNS limb，不能逐 limb 独立近似 Delta。
void encrypt_bfv_rns(const std::vector<uint64_t> &m, const RlweSk &sk,
                     size_t N, const std::vector<uint64_t> &qs, uint64_t t,
                     double sigma, std::mt19937_64 &rng, RlweCt &ct);

// Decrypt: per-limb phase, CRT-compose to MP, mod-switch q1 → drop, then
// rescale q0 → t. tables.q0_inv_mod_q1 must be set when K >= 2.
// phase=c0+c1*s 与本实现的 c0=-(a*s+e)+Delta*m、c1=a 约定配套。
// K=2 ciphertext 中的 Delta*m 来自同一个 composite-Q 整数表示，因此解密
// 也先恢复一致的 phase 表示，再进入 drop/rescale。
void decrypt_rns(const RlweCt &ct, const RlweSk &sk, size_t N,
                 const std::vector<uint64_t> &qs, uint64_t t,
                 const RnsTables &tables, RlwePt &pt);
