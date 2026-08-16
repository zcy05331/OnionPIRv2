#include "tests.h"

void PirTest::test_server_loader() {
  PirParams params = PirParams().with_layout({3, 2, true});
  PirServer server(params);
  size_t source_calls = 0;
  PlaintextSource source = [&](size_t index, RlwePt &out) {
    ++source_calls;
    out.data.resize(params.get_poly_degree());
    for (size_t i = 0; i < out.data.size(); ++i) {
      out.data[i] = (index + i) % params.get_plain_mod();
    }
  };

  // The shape rounds three logical rows to four. The callback runs only for
  // real rows; the loader creates and records a zero-filled padding row.
  server.load_data(3, source, {0, 2, 3});
  require_test(source_calls == 3, "source called for shape padding");
  require_test(server.direct_get_original_plaintext(0).data[7] == 7,
               "source row");
  require_test(server.direct_get_original_plaintext(2).data[7] == 9,
               "source row 2");
  require_test(server.direct_get_original_plaintext(3).data[7] == 0,
               "shape padding");

  // The legacy random-data API must traverse the same preprocessing path.
  PirServer random_server(params);
  random_server.gen_data({0, 3});
  require_test(random_server.direct_get_original_plaintext(0).data.size() ==
                   params.get_poly_degree(),
               "random source compatibility");
  require_test(random_server.direct_get_original_plaintext(3).data[7] <
                   params.get_plain_mod(),
               "random source coefficient range");

  // Validate callback output before it enters NTT preprocessing.
  bool rejected_bad_size = false;
  try {
    server.load_data(1, [&](size_t, RlwePt &out) {
      out.data.assign(params.get_poly_degree() - 1, 0);
    });
  } catch (const std::invalid_argument &) {
    rejected_bad_size = true;
  }
  require_test(rejected_bad_size, "accepted wrong plaintext coefficient count");

  bool rejected_bad_coefficient = false;
  try {
    server.load_data(1, [&](size_t, RlwePt &out) {
      out.data.assign(params.get_poly_degree(), 0);
      out.data[17] = params.get_plain_mod();
    });
  } catch (const std::invalid_argument &) {
    rejected_bad_coefficient = true;
  }
  require_test(rejected_bad_coefficient, "accepted coefficient outside plaintext modulus");
}
