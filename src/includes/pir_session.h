#pragma once

#include "bv_keyswitch.h"
#include "gsw.h"

#include <memory>

struct PirSessionKeys {
  bvks::BvGaloisKeys bv_galois_keys;
  GSWCt gsw_key;
};

using SharedPirSessionKeys = std::shared_ptr<const PirSessionKeys>;
