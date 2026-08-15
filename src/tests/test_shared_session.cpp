#include "tests.h"
#include "pir_session.h"

#include <array>
#include <sstream>

void PirTest::test_shared_session() {
  PirParams reference = PirParams().with_layout({349526, 10, true});
  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();

  const std::array<PirLayoutConfig, 3> layouts = {
      PirLayoutConfig{1, 0, true},
      PirLayoutConfig{43, 5, true},
      PirLayoutConfig{174763, 9, true},
  };
  for (const PirLayoutConfig &layout : layouts) {
    PirParams params = reference.with_layout(layout);
    require_test(reference.scheme_compatible(params),
                 "runtime layout changed the session scheme");

    PirServer server(params);
    server.set_client_session_keys(client.get_client_id(), keys);
    require_test(
        server.client_session_keys(client.get_client_id()).get() == keys.get(),
        "shared bundle identity");

    const size_t query_index = params.get_target_num_pt() - 1;
    PlaintextSource source = [&](size_t index, RlwePt &out) {
      out.data.resize(params.get_poly_degree());
      for (size_t coefficient = 0; coefficient < out.data.size();
           ++coefficient) {
        out.data[coefficient] =
            (17 * index + 3 * coefficient + 11) % params.get_plain_mod();
      }
    };
    server.load_data(params.get_target_num_pt(), source, {query_index});

    RlweCt query = client.fast_generate_query(params, query_index);
    RlweCt response = server.make_query(client.get_client_id(), query);
    std::stringstream response_stream;
    server.save_resp_to_stream(response, response_stream);
    RlweCt reconstructed = client.load_resp_from_stream(response_stream);
    RlwePt decrypted = client.decrypt_mod_q(reconstructed);
    RlwePt expected = server.direct_get_original_plaintext(query_index);
    require_test(utils::plaintext_is_equal(decrypted, expected),
                 "cross-layout encrypted retrieval mismatch");
  }

  bool rejected_out_of_range = false;
  try {
    (void)client.fast_generate_query(reference, reference.get_num_pt());
  } catch (const std::out_of_range &) {
    rejected_out_of_range = true;
  }
  require_test(rejected_out_of_range,
               "out-of-range query index reached encryption");
}
