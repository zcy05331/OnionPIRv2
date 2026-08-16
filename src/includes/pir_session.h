#pragma once

#include "bv_keyswitch.h"
#include "gsw.h"

#include <memory>

struct PirSessionKeys {
  // Scheme-level helper material only: the client secret key never enters this
  // bundle. Layout-specific database dimensions are deliberately absent, so
  // one immutable bundle can serve every compatible Merkle level.
  bvks::BvGaloisKeys bv_galois_keys;
  GSWCt gsw_key;
};

// Sharing avoids copying the helper bundle into every layer server. Const
// ownership prevents any server from mutating keys used by another level.
using SharedPirSessionKeys = std::shared_ptr<const PirSessionKeys>;
