#include "layer_layout_planner.h"

#include "utils.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <tuple>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Features and enumeration
// ---------------------------------------------------------------------------

uint64_t checked_mul(uint64_t a, uint64_t b, const char *what) {
  if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
    throw std::overflow_error(std::string(what) + " overflows uint64_t");
  }
  return a * b;
}

size_t node_count_of_level(size_t level) {
  if (level == 0 || level >= std::numeric_limits<size_t>::digits) {
    throw std::invalid_argument("layer planner: level out of range");
  }
  return size_t{1} << level;
}

std::tuple<size_t, size_t, size_t, size_t> legacy_score(
    const LayerLayoutCandidate &c) {
  const PirParams &p = c.layout.params;
  return std::make_tuple(p.get_num_pt(), c.features.useful_expanded_ciphertexts,
                         p.get_num_other_dims(), p.get_expan_height());
}

// ---------------------------------------------------------------------------
// Minimal JSON (writer helpers + strict reader), enough for the profile file.
// ---------------------------------------------------------------------------

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
  bool boolean = false;
  double number = 0.0;
  std::string raw_number;  // exact integer text for uint64 fields
  std::string str;
  std::vector<JsonValue> array;
  std::vector<std::pair<std::string, JsonValue>> object;

  const JsonValue &at(const std::string &key) const {
    for (const auto &[k, v] : object) {
      if (k == key) return v;
    }
    throw std::invalid_argument("layer layout profile: missing key \"" + key +
                                "\"");
  }
  bool has(const std::string &key) const {
    for (const auto &[k, v] : object) {
      if (k == key) return true;
    }
    return false;
  }
  uint64_t as_u64() const {
    if (type != Type::Number) {
      throw std::invalid_argument("layer layout profile: expected a number");
    }
    if (raw_number.find_first_of(".eE") == std::string::npos) {
      return std::stoull(raw_number);
    }
    if (number < 0 || number != std::floor(number)) {
      throw std::invalid_argument(
          "layer layout profile: expected a non-negative integer");
    }
    return static_cast<uint64_t>(number);
  }
  double as_double() const {
    if (type != Type::Number) {
      throw std::invalid_argument("layer layout profile: expected a number");
    }
    return number;
  }
  const std::string &as_string() const {
    if (type != Type::String) {
      throw std::invalid_argument("layer layout profile: expected a string");
    }
    return str;
  }
  bool as_bool() const {
    if (type != Type::Bool) {
      throw std::invalid_argument("layer layout profile: expected a boolean");
    }
    return boolean;
  }
  const std::vector<JsonValue> &as_array() const {
    if (type != Type::Array) {
      throw std::invalid_argument("layer layout profile: expected an array");
    }
    return array;
  }
};

class JsonParser {
 public:
  explicit JsonParser(const std::string &text) : text_(text) {}

  JsonValue parse_document() {
    JsonValue value = parse_value();
    skip_ws();
    if (pos_ != text_.size()) fail("trailing characters");
    return value;
  }

 private:
  const std::string &text_;
  size_t pos_ = 0;

  [[noreturn]] void fail(const char *what) const {
    throw std::invalid_argument(std::string("layer layout profile JSON: ") +
                                what + " at offset " + std::to_string(pos_));
  }
  void skip_ws() {
    while (pos_ < text_.size() &&
           (text_[pos_] == ' ' || text_[pos_] == '\n' || text_[pos_] == '\r' ||
            text_[pos_] == '\t')) {
      ++pos_;
    }
  }
  bool consume(char c) {
    skip_ws();
    if (pos_ < text_.size() && text_[pos_] == c) {
      ++pos_;
      return true;
    }
    return false;
  }
  void expect(char c) {
    if (!consume(c)) fail("unexpected character");
  }
  JsonValue parse_value() {
    skip_ws();
    if (pos_ >= text_.size()) fail("unexpected end of input");
    const char c = text_[pos_];
    JsonValue v;
    if (c == '{') {
      v.type = JsonValue::Type::Object;
      ++pos_;
      if (consume('}')) return v;
      do {
        skip_ws();
        std::string key = parse_string();
        expect(':');
        JsonValue member = parse_value();
        v.object.emplace_back(std::move(key), std::move(member));
      } while (consume(','));
      expect('}');
      return v;
    }
    if (c == '[') {
      v.type = JsonValue::Type::Array;
      ++pos_;
      if (consume(']')) return v;
      do {
        v.array.push_back(parse_value());
      } while (consume(','));
      expect(']');
      return v;
    }
    if (c == '"') {
      v.type = JsonValue::Type::String;
      v.str = parse_string();
      return v;
    }
    if (text_.compare(pos_, 4, "true") == 0) {
      v.type = JsonValue::Type::Bool;
      v.boolean = true;
      pos_ += 4;
      return v;
    }
    if (text_.compare(pos_, 5, "false") == 0) {
      v.type = JsonValue::Type::Bool;
      pos_ += 5;
      return v;
    }
    if (text_.compare(pos_, 4, "null") == 0) {
      pos_ += 4;
      return v;
    }
    // number
    const size_t start = pos_;
    while (pos_ < text_.size() &&
           (std::isdigit(static_cast<unsigned char>(text_[pos_])) ||
            text_[pos_] == '-' || text_[pos_] == '+' || text_[pos_] == '.' ||
            text_[pos_] == 'e' || text_[pos_] == 'E')) {
      ++pos_;
    }
    if (start == pos_) fail("unexpected character");
    v.type = JsonValue::Type::Number;
    v.raw_number = text_.substr(start, pos_ - start);
    v.number = std::stod(v.raw_number);
    return v;
  }
  std::string parse_string() {
    expect('"');
    std::string out;
    while (true) {
      if (pos_ >= text_.size()) fail("unterminated string");
      const char c = text_[pos_++];
      if (c == '"') break;
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (pos_ >= text_.size()) fail("bad escape");
      const char e = text_[pos_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (pos_ + 4 > text_.size()) fail("bad unicode escape");
          const unsigned code =
              static_cast<unsigned>(std::stoul(text_.substr(pos_, 4), nullptr, 16));
          pos_ += 4;
          if (code < 0x80) {
            out.push_back(static_cast<char>(code));
          } else {
            fail("non-ASCII unicode escapes are not supported");
          }
          break;
        }
        default: fail("bad escape");
      }
    }
    return out;
  }
};

std::string json_quote(const std::string &value) {
  std::ostringstream out;
  out << '"';
  for (unsigned char c : value) {
    switch (c) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<unsigned>(c) << std::dec;
        } else {
          out << c;
        }
    }
  }
  out << '"';
  return out.str();
}

void write_features(std::ostringstream &out, const LayerLayoutFeatures &f,
                    const char *indent) {
  out << indent << "\"expansion_height\": " << f.expansion_height << ",\n"
      << indent << "\"first_dim_size\": " << f.first_dim_size << ",\n"
      << indent << "\"other_dim_size\": " << f.other_dim_size << ",\n"
      << indent << "\"other_dim_count\": " << f.other_dim_count << ",\n"
      << indent << "\"padded_plaintexts\": " << f.padded_plaintexts << ",\n"
      << indent << "\"padding_plaintexts\": " << f.padding_plaintexts << ",\n"
      << indent << "\"useful_expanded_ciphertexts\": "
      << f.useful_expanded_ciphertexts << ",\n"
      << indent << "\"expansion_substitutions\": " << f.expansion_substitutions
      << ",\n"
      << indent << "\"first_dim_query_ntts\": " << f.first_dim_query_ntts
      << ",\n"
      << indent << "\"selector_rows_to_complete\": "
      << f.selector_rows_to_complete << ",\n"
      << indent << "\"crt_coefficients_to_compose\": "
      << f.crt_coefficients_to_compose << ",\n"
      << indent << "\"inverse_ntts\": " << f.inverse_ntts << ",\n"
      << indent << "\"cmux_count\": " << f.cmux_count << ",\n"
      << indent << "\"logical_padded_bytes\": " << f.logical_padded_bytes
      << ",\n"
      << indent << "\"physical_scan_bytes\": " << f.physical_scan_bytes;
}

LayerLayoutFeatures read_features(const JsonValue &v) {
  LayerLayoutFeatures f;
  f.expansion_height = v.at("expansion_height").as_u64();
  f.first_dim_size = v.at("first_dim_size").as_u64();
  f.other_dim_size = v.at("other_dim_size").as_u64();
  f.other_dim_count = v.at("other_dim_count").as_u64();
  f.padded_plaintexts = v.at("padded_plaintexts").as_u64();
  f.padding_plaintexts = v.at("padding_plaintexts").as_u64();
  f.useful_expanded_ciphertexts = v.at("useful_expanded_ciphertexts").as_u64();
  f.expansion_substitutions = v.at("expansion_substitutions").as_u64();
  f.first_dim_query_ntts = v.at("first_dim_query_ntts").as_u64();
  f.selector_rows_to_complete = v.at("selector_rows_to_complete").as_u64();
  f.crt_coefficients_to_compose = v.at("crt_coefficients_to_compose").as_u64();
  f.inverse_ntts = v.at("inverse_ntts").as_u64();
  f.cmux_count = v.at("cmux_count").as_u64();
  f.logical_padded_bytes = v.at("logical_padded_bytes").as_u64();
  f.physical_scan_bytes = v.at("physical_scan_bytes").as_u64();
  return f;
}

std::string detect_cpu_model() {
#if defined(__APPLE__)
  char buffer[256];
  size_t length = sizeof(buffer);
  if (sysctlbyname("machdep.cpu.brand_string", buffer, &length, nullptr, 0) ==
      0) {
    return std::string(buffer, length > 0 ? length - 1 : 0);
  }
  return "unknown";
#else
  std::ifstream cpuinfo("/proc/cpuinfo");
  std::string line;
  while (std::getline(cpuinfo, line)) {
    if (line.rfind("model name", 0) == 0) {
      const size_t colon = line.find(':');
      if (colon != std::string::npos) {
        size_t start = colon + 1;
        while (start < line.size() && line[start] == ' ') ++start;
        return line.substr(start);
      }
    }
  }
  return "unknown";
#endif
}

double median_of(std::vector<double> values) {
  if (values.empty()) {
    throw std::invalid_argument("layer layout profile: empty sample set");
  }
  std::sort(values.begin(), values.end());
  const size_t n = values.size();
  return n % 2 == 1 ? values[n / 2]
                    : 0.5 * (values[n / 2 - 1] + values[n / 2]);
}

bool same_shape(const LayerLayoutFeatures &a, const LayerLayoutFeatures &b) {
  return a.expansion_height == b.expansion_height &&
         a.first_dim_size == b.first_dim_size &&
         a.other_dim_size == b.other_dim_size &&
         a.other_dim_count == b.other_dim_count &&
         a.padded_plaintexts == b.padded_plaintexts;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public geometry and enumeration
// ---------------------------------------------------------------------------

size_t count_pruned_expansion_substitutions(size_t useful, size_t height) {
  if (height >= std::numeric_limits<size_t>::digits) {
    throw std::invalid_argument("expansion height too large");
  }
  const size_t capacity = size_t{1} << height;
  size_t count = 0;
  for (size_t i = 1; i < capacity; ++i) {
    const size_t k = size_t{1} << (std::bit_width(i) - 1);
    const size_t left_leaf = i * capacity / k - capacity;
    if (left_leaf < useful) ++count;
  }
  return count;
}

LayerLayoutFeatures compute_layer_layout_features(const PirParams &params) {
  LayerLayoutFeatures f;
  f.expansion_height = params.get_expan_height();
  f.first_dim_size = params.get_fst_dim_sz();
  f.other_dim_size = params.get_other_dim_sz();
  f.other_dim_count = params.get_num_other_dims();
  f.padded_plaintexts = params.get_num_pt();
  f.padding_plaintexts = params.get_num_pt() - params.get_target_num_pt();
  f.useful_expanded_ciphertexts =
      params.get_fst_dim_sz() + params.get_l() * params.get_num_other_dims();
  f.expansion_substitutions = count_pruned_expansion_substitutions(
      f.useful_expanded_ciphertexts, f.expansion_height);
  f.first_dim_query_ntts = 2 * params.get_fst_dim_sz();
  f.selector_rows_to_complete = params.get_l() * params.get_num_other_dims();
  f.crt_coefficients_to_compose =
      params.get_composite_rns().enabled
          ? 2 * params.get_poly_degree() * params.get_other_dim_sz()
          : 0;
  f.inverse_ntts = 2 * params.get_other_dim_sz();
  f.cmux_count = params.get_other_dim_sz() - 1;
  f.logical_padded_bytes =
      checked_mul(params.get_num_pt(), params.get_pt_size(), "padded bytes");
  f.physical_scan_bytes = checked_mul(
      checked_mul(params.get_num_pt(), params.get_coeff_val_cnt(),
                  "scan coefficients"),
      sizeof(uint64_t), "physical scan bytes");
  return f;
}

std::vector<LayerLayoutCandidate> enumerate_layer_layout_candidates(
    size_t level, size_t nodes_per_pt, const PirParams &reference) {
  if (nodes_per_pt == 0) {
    throw std::invalid_argument("layer planner: nodes per plaintext must be positive");
  }
  const size_t node_count = node_count_of_level(level);
  const size_t target_num_pt = utils::roundup_div(node_count, nodes_per_pt);
  const size_t max_other_dims = reference.get_num_other_dims();

  std::vector<LayerLayoutCandidate> candidates;
  for (size_t height = 0; height <= reference.get_expan_height(); ++height) {
    PirParams params = reference;
    try {
      params = reference.with_layout(
          {target_num_pt, height, reference.get_fst_dim_pow2()});
    } catch (const std::runtime_error &) {
      continue;  // this height cannot represent the level
    }
    if (params.get_num_other_dims() > max_other_dims) continue;
    if (!reference.scheme_compatible(params)) continue;
    LayerLayoutCandidate c;
    c.layout = {level, node_count, target_num_pt, params};
    c.layout.direct_return = node_count <= nodes_per_pt;
    c.features = compute_layer_layout_features(params);
    candidates.push_back(std::move(c));
  }
  if (candidates.empty()) {
    throw std::runtime_error("No scheme-compatible PIR layout for Merkle layer");
  }
  std::stable_sort(candidates.begin(), candidates.end(),
                   [](const LayerLayoutCandidate &a,
                      const LayerLayoutCandidate &b) {
                     return std::make_tuple(a.features.expansion_height,
                                            a.features.first_dim_size,
                                            a.features.other_dim_size) <
                            std::make_tuple(b.features.expansion_height,
                                            b.features.first_dim_size,
                                            b.features.other_dim_size);
                   });
  return candidates;
}

size_t legacy_layer_layout_candidate(
    const std::vector<LayerLayoutCandidate> &candidates) {
  if (candidates.empty()) {
    throw std::invalid_argument("layer planner: no candidates");
  }
  size_t best = 0;
  for (size_t i = 1; i < candidates.size(); ++i) {
    if (legacy_score(candidates[i]) < legacy_score(candidates[best])) best = i;
  }
  return best;
}

std::vector<LayerLayoutCandidate> pareto_layer_layout_candidates(
    const std::vector<LayerLayoutCandidate> &candidates) {
  const auto dominates = [](const LayerLayoutFeatures &a,
                            const LayerLayoutFeatures &b) {
    const bool no_worse = a.physical_scan_bytes <= b.physical_scan_bytes &&
                          a.expansion_substitutions <= b.expansion_substitutions &&
                          a.first_dim_query_ntts <= b.first_dim_query_ntts &&
                          a.selector_rows_to_complete <=
                              b.selector_rows_to_complete &&
                          a.inverse_ntts <= b.inverse_ntts &&
                          a.cmux_count <= b.cmux_count;
    const bool better = a.physical_scan_bytes < b.physical_scan_bytes ||
                        a.expansion_substitutions < b.expansion_substitutions ||
                        a.first_dim_query_ntts < b.first_dim_query_ntts ||
                        a.selector_rows_to_complete <
                            b.selector_rows_to_complete ||
                        a.inverse_ntts < b.inverse_ntts ||
                        a.cmux_count < b.cmux_count;
    return no_worse && better;
  };
  std::vector<LayerLayoutCandidate> frontier;
  for (size_t i = 0; i < candidates.size(); ++i) {
    bool dominated = false;
    for (size_t j = 0; j < candidates.size() && !dominated; ++j) {
      if (i != j && dominates(candidates[j].features, candidates[i].features)) {
        dominated = true;
      }
    }
    if (!dominated) frontier.push_back(candidates[i]);
  }
  return frontier;
}

// ---------------------------------------------------------------------------
// Profile environment, JSON I/O, validation
// ---------------------------------------------------------------------------

LayerLayoutProfileEnvironment detect_layer_layout_environment(
    const PirParams &reference, const std::string &commit,
    const std::string &build_type, const std::string &config) {
  LayerLayoutProfileEnvironment env;
  env.commit = commit;
  env.build_type = build_type;
  env.config = config;
  env.cpu = detect_cpu_model();
#if defined(__x86_64__)
  env.architecture = "x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
  env.architecture = "arm64";
#else
  env.architecture = "unknown";
#endif
  env.compiler = __VERSION__;
  env.hexl_version = "1.2.6";
  env.poly_degree = reference.get_poly_degree();
  env.log_q = reference.get_ct_mod_width();
  env.log_t = std::bit_width(reference.get_plain_mod());
  env.log_q_prime = std::bit_width(reference.get_small_q() - 1);
  env.l_ep = reference.get_l();
  env.l_key = reference.get_l_key();
  env.l_ks = DBConsts::L_KS;
  env.composite_first_dim = reference.get_composite_rns().enabled;
  return env;
}

void save_layer_layout_profile(const LayerLayoutProfile &profile,
                               const std::string &path) {
  std::ostringstream out;
  out << std::setprecision(17);
  const auto &e = profile.environment;
  out << "{\n  \"schema_version\": " << json_quote(profile.schema_version)
      << ",\n  \"environment\": {\n"
      << "    \"commit\": " << json_quote(e.commit) << ",\n"
      << "    \"build_type\": " << json_quote(e.build_type) << ",\n"
      << "    \"config\": " << json_quote(e.config) << ",\n"
      << "    \"cpu\": " << json_quote(e.cpu) << ",\n"
      << "    \"architecture\": " << json_quote(e.architecture) << ",\n"
      << "    \"compiler\": " << json_quote(e.compiler) << ",\n"
      << "    \"hexl_version\": " << json_quote(e.hexl_version) << ",\n"
      << "    \"poly_degree\": " << e.poly_degree << ",\n"
      << "    \"log_q\": " << e.log_q << ",\n"
      << "    \"log_t\": " << e.log_t << ",\n"
      << "    \"log_q_prime\": " << e.log_q_prime << ",\n"
      << "    \"L_EP\": " << e.l_ep << ",\n"
      << "    \"L_KEY\": " << e.l_key << ",\n"
      << "    \"L_KS\": " << e.l_ks << ",\n"
      << "    \"composite_first_dim\": "
      << (e.composite_first_dim ? "true" : "false") << "\n  },\n"
      << "  \"tree_height\": " << profile.tree_height << ",\n"
      << "  \"nodes_per_plaintext\": " << profile.nodes_per_plaintext << ",\n"
      << "  \"warmups\": " << profile.warmups << ",\n"
      << "  \"measured_trials\": " << profile.measured_trials << ",\n"
      << "  \"trial_seed\": " << profile.trial_seed << ",\n"
      << "  \"padding_budget\": " << profile.padding_budget << ",\n"
      << "  \"legacy_total_padded_plaintexts\": "
      << profile.legacy_total_padded_plaintexts << ",\n"
      << "  \"selected_total_padded_plaintexts\": "
      << profile.selected_total_padded_plaintexts << ",\n"
      << "  \"selected_expansion_heights\": [";
  for (size_t i = 0; i < profile.selected_expansion_heights.size(); ++i) {
    out << (i ? ", " : "") << profile.selected_expansion_heights[i];
  }
  out << "],\n  \"measurements\": [";
  for (size_t i = 0; i < profile.measurements.size(); ++i) {
    const LayerLayoutMeasurement &m = profile.measurements[i];
    out << (i ? ",\n    {\n" : "\n    {\n")
        << "      \"level\": " << m.level << ",\n";
    write_features(out, m.features, "      ");
    out << ",\n      \"dominated\": " << (m.dominated ? "true" : "false")
        << ",\n      \"median_server_ms\": " << m.median_server_ms
        << ",\n      \"server_samples_ms\": [";
    for (size_t j = 0; j < m.server_samples_ms.size(); ++j) {
      out << (j ? ", " : "") << m.server_samples_ms[j];
    }
    out << "]\n    }";
  }
  out << (profile.measurements.empty() ? "]\n}\n" : "\n  ]\n}\n");

  const std::string tmp = path + ".tmp";
  {
    std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
    if (!file) {
      throw std::runtime_error("cannot write layer layout profile: " + tmp);
    }
    file << out.str();
    file.flush();
    if (!file) {
      throw std::runtime_error("cannot flush layer layout profile: " + tmp);
    }
  }
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    throw std::runtime_error("cannot rename layer layout profile into place: " +
                             path);
  }
}

LayerLayoutProfile load_layer_layout_profile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("cannot read layer layout profile: " + path);
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  const std::string text = buffer.str();
  JsonValue root = JsonParser(text).parse_document();

  LayerLayoutProfile profile;
  profile.schema_version = root.at("schema_version").as_string();
  if (profile.schema_version != "layer-layout-profile-v1") {
    throw std::invalid_argument("unsupported layer layout profile schema: " +
                                profile.schema_version);
  }
  const JsonValue &e = root.at("environment");
  auto &env = profile.environment;
  env.commit = e.at("commit").as_string();
  env.build_type = e.at("build_type").as_string();
  env.config = e.at("config").as_string();
  env.cpu = e.at("cpu").as_string();
  env.architecture = e.at("architecture").as_string();
  env.compiler = e.at("compiler").as_string();
  env.hexl_version = e.at("hexl_version").as_string();
  env.poly_degree = e.at("poly_degree").as_u64();
  env.log_q = e.at("log_q").as_u64();
  env.log_t = e.at("log_t").as_u64();
  env.log_q_prime = e.at("log_q_prime").as_u64();
  env.l_ep = e.at("L_EP").as_u64();
  env.l_key = e.at("L_KEY").as_u64();
  env.l_ks = e.at("L_KS").as_u64();
  env.composite_first_dim = e.at("composite_first_dim").as_bool();
  profile.tree_height = root.at("tree_height").as_u64();
  profile.nodes_per_plaintext = root.at("nodes_per_plaintext").as_u64();
  profile.warmups = root.at("warmups").as_u64();
  profile.measured_trials = root.at("measured_trials").as_u64();
  profile.trial_seed = root.at("trial_seed").as_u64();
  profile.padding_budget = root.at("padding_budget").as_double();
  profile.legacy_total_padded_plaintexts =
      root.at("legacy_total_padded_plaintexts").as_u64();
  profile.selected_total_padded_plaintexts =
      root.at("selected_total_padded_plaintexts").as_u64();
  for (const JsonValue &h : root.at("selected_expansion_heights").as_array()) {
    profile.selected_expansion_heights.push_back(h.as_u64());
  }
  for (const JsonValue &m : root.at("measurements").as_array()) {
    LayerLayoutMeasurement measurement;
    measurement.level = m.at("level").as_u64();
    measurement.features = read_features(m);
    measurement.dominated = m.at("dominated").as_bool();
    measurement.median_server_ms = m.at("median_server_ms").as_double();
    for (const JsonValue &s : m.at("server_samples_ms").as_array()) {
      measurement.server_samples_ms.push_back(s.as_double());
    }
    if (measurement.server_samples_ms.empty()) {
      throw std::invalid_argument(
          "layer layout profile: a measurement has no samples");
    }
    profile.measurements.push_back(std::move(measurement));
  }
  return profile;
}

std::string describe_layer_layout_profile_mismatch(
    const LayerLayoutProfile &profile,
    const LayerLayoutProfileEnvironment &runtime, size_t tree_height,
    size_t nodes_per_pt) {
  const auto &e = profile.environment;
  const auto mismatch = [](const std::string &field, const std::string &have,
                           const std::string &want) {
    return "layer layout profile " + field + " mismatch: profile has \"" +
           have + "\", runtime has \"" + want + "\"";
  };
  const auto num = [](size_t v) { return std::to_string(v); };
  if (e.poly_degree != runtime.poly_degree)
    return mismatch("poly_degree", num(e.poly_degree), num(runtime.poly_degree));
  if (e.log_q != runtime.log_q)
    return mismatch("log_q", num(e.log_q), num(runtime.log_q));
  if (e.log_t != runtime.log_t)
    return mismatch("log_t", num(e.log_t), num(runtime.log_t));
  if (e.log_q_prime != runtime.log_q_prime)
    return mismatch("log_q_prime", num(e.log_q_prime), num(runtime.log_q_prime));
  if (e.l_ep != runtime.l_ep) return mismatch("L_EP", num(e.l_ep), num(runtime.l_ep));
  if (e.l_key != runtime.l_key)
    return mismatch("L_KEY", num(e.l_key), num(runtime.l_key));
  if (e.l_ks != runtime.l_ks) return mismatch("L_KS", num(e.l_ks), num(runtime.l_ks));
  if (e.composite_first_dim != runtime.composite_first_dim)
    return mismatch("composite_first_dim", e.composite_first_dim ? "true" : "false",
                    runtime.composite_first_dim ? "true" : "false");
  if (profile.nodes_per_plaintext != nodes_per_pt)
    return mismatch("nodes_per_plaintext", num(profile.nodes_per_plaintext),
                    num(nodes_per_pt));
  if (profile.tree_height != tree_height)
    return mismatch("tree_height", num(profile.tree_height), num(tree_height));
  if (e.architecture != runtime.architecture)
    return mismatch("architecture", e.architecture, runtime.architecture);
  if (e.cpu != runtime.cpu) return mismatch("cpu", e.cpu, runtime.cpu);
  if (e.compiler != runtime.compiler)
    return mismatch("compiler", e.compiler, runtime.compiler);
  if (e.hexl_version != runtime.hexl_version)
    return mismatch("hexl_version", e.hexl_version, runtime.hexl_version);
  return "";
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

LayerLayoutSelection select_layer_layouts(const LayerLayoutProfile &profile,
                                          size_t tree_height,
                                          size_t nodes_per_pt,
                                          const PirParams &reference,
                                          double padding_budget) {
  if (!(padding_budget >= 1.0)) {
    throw std::invalid_argument("layer padding budget must be >= 1.0");
  }
  if (tree_height == 0) {
    throw std::invalid_argument("layer planner: empty tree");
  }

  struct Option {
    size_t height = 0;
    size_t extra_plaintexts = 0;  // relative to the legacy layout of the level
    double median_ms = 0.0;
    LayerLayoutFeatures features;
  };
  struct LevelPlan {
    size_t legacy_height = 0;
    size_t legacy_num_pt = 0;
    double legacy_median_ms = 0.0;  // 0 when unmeasured
    std::vector<Option> options;    // measured candidates only
  };

  std::vector<LevelPlan> plans(tree_height);
  uint64_t legacy_total = 0;
  for (size_t level = 1; level <= tree_height; ++level) {
    LevelPlan &plan = plans[level - 1];
    const std::vector<LayerLayoutCandidate> candidates =
        enumerate_layer_layout_candidates(level, nodes_per_pt, reference);
    const size_t legacy = legacy_layer_layout_candidate(candidates);
    plan.legacy_height = candidates[legacy].features.expansion_height;
    plan.legacy_num_pt = candidates[legacy].features.padded_plaintexts;
    legacy_total += plan.legacy_num_pt;
    const bool direct = candidates[legacy].layout.direct_return;
    for (const LayerLayoutMeasurement &m : profile.measurements) {
      if (m.level != level) continue;
      const auto it = std::find_if(
          candidates.begin(), candidates.end(),
          [&](const LayerLayoutCandidate &c) {
            return c.features.expansion_height == m.features.expansion_height;
          });
      if (it == candidates.end() || !same_shape(it->features, m.features)) {
        throw std::invalid_argument(
            "layer layout profile: level " + std::to_string(level) +
            " height " + std::to_string(m.features.expansion_height) +
            " does not match a legal runtime layout");
      }
      if (direct) continue;  // served in the clear: no PIR layout to choose
      Option option;
      option.height = m.features.expansion_height;
      option.extra_plaintexts =
          m.features.padded_plaintexts - plan.legacy_num_pt;
      option.median_ms = m.median_server_ms;
      option.features = it->features;
      if (option.height == plan.legacy_height) {
        plan.legacy_median_ms = option.median_ms;
      }
      plan.options.push_back(option);
    }
  }

  const uint64_t cap_total = static_cast<uint64_t>(
      std::floor(static_cast<double>(legacy_total) * padding_budget));
  const size_t cap_extra =
      cap_total > legacy_total ? static_cast<size_t>(cap_total - legacy_total)
                               : 0;

  // dp[e] = minimal predicted time using exactly e extra plaintexts so far.
  constexpr double kInf = std::numeric_limits<double>::infinity();
  std::vector<double> dp(cap_extra + 1, kInf);
  dp[0] = 0.0;
  std::vector<std::vector<int>> choice(tree_height,
                                       std::vector<int>(cap_extra + 1, -1));
  for (size_t level = 1; level <= tree_height; ++level) {
    const LevelPlan &plan = plans[level - 1];
    std::vector<double> next(cap_extra + 1, kInf);
    if (plan.options.empty()) {
      next = dp;  // legacy layout, no measured time
      continue;
    }
    for (size_t e = 0; e <= cap_extra; ++e) {
      if (dp[e] == kInf) continue;
      for (size_t o = 0; o < plan.options.size(); ++o) {
        const size_t ne = e + plan.options[o].extra_plaintexts;
        if (ne > cap_extra) continue;
        const double t = dp[e] + plan.options[o].median_ms;
        if (t < next[ne]) {
          next[ne] = t;
          choice[level - 1][ne] = static_cast<int>(o);
        }
      }
    }
    dp = std::move(next);
  }
  size_t best_e = 0;
  for (size_t e = 0; e <= cap_extra; ++e) {
    if (dp[e] < dp[best_e]) best_e = e;
  }
  if (dp[best_e] == kInf) {
    throw std::runtime_error(
        "layer layout profile: no measured combination fits the budget");
  }

  LayerLayoutSelection selection;
  selection.expansion_heights.assign(tree_height, 0);
  selection.legacy_total_padded_plaintexts = legacy_total;
  std::vector<int> chosen(tree_height, -1);
  size_t e = best_e;
  for (size_t level = tree_height; level >= 1; --level) {
    const LevelPlan &plan = plans[level - 1];
    if (!plan.options.empty()) {
      const int o = choice[level - 1][e];
      if (o < 0) {
        throw std::logic_error("layer layout selection lost its DP trace");
      }
      chosen[level - 1] = o;
      e -= plan.options[o].extra_plaintexts;
    }
    if (level == 1) break;
  }

  // Tie refinement: a candidate within 2% of the chosen median that is
  // preferred by the deterministic order and does not add padding replaces
  // the choice.
  const auto tie_key = [](const Option &o) {
    return std::make_tuple(o.features.physical_scan_bytes,
                           o.features.expansion_substitutions,
                           o.features.inverse_ntts, o.height);
  };
  uint64_t selected_total = 0;
  for (size_t level = 1; level <= tree_height; ++level) {
    LevelPlan &plan = plans[level - 1];
    size_t height = plan.legacy_height;
    size_t num_pt = plan.legacy_num_pt;
    double median = plan.legacy_median_ms;
    if (chosen[level - 1] >= 0) {
      Option pick = plan.options[static_cast<size_t>(chosen[level - 1])];
      for (const Option &alt : plan.options) {
        if (alt.extra_plaintexts <= pick.extra_plaintexts &&
            alt.median_ms <= pick.median_ms * 1.02 &&
            tie_key(alt) < tie_key(pick)) {
          pick = alt;
        }
      }
      height = pick.height;
      num_pt = plan.legacy_num_pt + pick.extra_plaintexts;
      median = pick.median_ms;
    }
    selection.expansion_heights[level - 1] = height;
    selected_total += num_pt;
    selection.predicted_selected_ms += median;
    selection.predicted_legacy_ms += plan.legacy_median_ms;
  }
  selection.selected_total_padded_plaintexts = selected_total;
  return selection;
}

// ---------------------------------------------------------------------------
// Policy-aware planner entry
// ---------------------------------------------------------------------------

const char *layer_layout_policy_name(LayerLayoutPolicy policy) {
  switch (policy) {
    case LayerLayoutPolicy::legacy_padding: return "legacy";
    case LayerLayoutPolicy::profiled: return "profiled";
  }
  return "unknown";
}

std::vector<LayerLayout> plan_layer_layouts(size_t tree_height,
                                            size_t nodes_per_pt,
                                            const PirParams &reference,
                                            const LayerPlannerConfig &config) {
  if (config.policy == LayerLayoutPolicy::legacy_padding) {
    return plan_layer_layouts(tree_height, nodes_per_pt, reference);
  }
  if (!config.profile) {
    throw std::invalid_argument(
        "profiled layer layout policy needs a layout profile");
  }
  const LayerLayoutProfileEnvironment runtime = detect_layer_layout_environment(
      reference, config.profile->environment.commit,
      config.profile->environment.build_type,
      config.profile->environment.config);
  const std::string mismatch = describe_layer_layout_profile_mismatch(
      *config.profile, runtime, tree_height, nodes_per_pt);
  if (!mismatch.empty()) {
    if (!config.allow_profile_fallback) {
      throw std::invalid_argument(mismatch);
    }
    return plan_layer_layouts(tree_height, nodes_per_pt, reference);
  }
  const LayerLayoutSelection selection = select_layer_layouts(
      *config.profile, tree_height, nodes_per_pt, reference,
      config.total_padding_budget);

  std::vector<LayerLayout> layouts;
  layouts.reserve(tree_height);
  for (size_t level = 1; level <= tree_height; ++level) {
    const std::vector<LayerLayoutCandidate> candidates =
        enumerate_layer_layout_candidates(level, nodes_per_pt, reference);
    const size_t height = selection.expansion_heights[level - 1];
    const auto it = std::find_if(
        candidates.begin(), candidates.end(),
        [&](const LayerLayoutCandidate &c) {
          return c.features.expansion_height == height;
        });
    if (it == candidates.end()) {
      throw std::logic_error("selected expansion height is not a legal layout");
    }
    layouts.push_back(it->layout);
  }
  return layouts;
}
