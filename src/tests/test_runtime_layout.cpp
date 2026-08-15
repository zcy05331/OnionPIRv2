#include "tests.h"

void PirTest::test_runtime_layout() {
  PirParams defaults;

  const PirLayoutConfig flat{349526, 10, true};
  PirParams flat_params = defaults.with_layout(flat);
  require_test(flat_params.get_target_num_pt() == 349526, "flat target");
  require_test(flat_params.get_fst_dim_sz() == 512, "flat first dimension");
  require_test(flat_params.get_num_dims() == 11, "flat dimension count");
  require_test(flat_params.get_num_pt() == 349696, "flat rounded shape");
  require_test(flat_params.get_expan_height() == 10,
               "flat expansion height");
  require_test(defaults.scheme_compatible(flat_params),
               "runtime layout changed scheme parameters");

  PirParams singleton = defaults.with_layout({1, 0, true});
  require_test(singleton.get_num_pt() == 1, "singleton shape");
  require_test(singleton.get_num_dims() == 1, "singleton dimension count");
  require_test(singleton.get_expan_height() == 0,
               "singleton expansion height");

  auto [tight_fst, tight_dims] =
      utils::calculate_db_shape(43, DBConsts::L_EP, 5, false);
  require_test(tight_fst == 26 && tight_dims == 2,
               "explicit non-power-of-two first dimension policy");

  bool rejected_zero = false;
  try {
    (void)defaults.with_layout({0, 0, true});
  } catch (const std::invalid_argument &) {
    rejected_zero = true;
  }
  require_test(rejected_zero, "zero target plaintext count was accepted");
}
