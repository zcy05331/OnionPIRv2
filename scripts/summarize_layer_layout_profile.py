#!/usr/bin/env python3
"""Deterministic summary of a layer-layout profile and optional A/B reports.

Usage:
  summarize_layer_layout_profile.py PROFILE.json [LEGACY.json PROFILED.json]

Prints, level by level, every measured candidate (expansion height, first
dimension, remaining candidates, padded plaintexts, median server ms), marks
the legacy and selected layouts, and attributes the predicted gain to fewer
candidates/INTTs/CMuxes versus more expansion work. With two merkle
benchmark JSONs it also compares the layerwise cases (mean, median, phases,
communication, padded bytes). Output is plain text, sorted, with no
timestamps, so two runs over the same inputs are byte-identical.
"""
import json
import statistics
import sys


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def summarize_profile(profile):
    H = profile["tree_height"]
    by_level = {}
    for m in profile["measurements"]:
        by_level.setdefault(m["level"], []).append(m)
    selected = profile.get("selected_expansion_heights", [])
    print(f"profile: H={H}, nodes/pt={profile['nodes_per_plaintext']}, "
          f"trials={profile['warmups']}+{profile['measured_trials']}, "
          f"budget={profile['padding_budget']}")
    env = profile["environment"]
    print(f"machine: {env['cpu']} ({env['architecture']}), {env['compiler']}, "
          f"HEXL {env['hexl_version']}, commit {env['commit'] or '-'}")
    print(f"padded plaintexts: legacy {profile['legacy_total_padded_plaintexts']}, "
          f"selected {profile['selected_total_padded_plaintexts']}")
    print()
    print("level  h  N0   Nrest  num_pt   subs  intt  cmux   median_ms  role")
    legacy_sum = 0.0
    selected_sum = 0.0
    for level in sorted(by_level):
        rows = sorted(by_level[level], key=lambda m: m["expansion_height"])
        legacy = min(rows, key=lambda m: (m["padded_plaintexts"],
                                          m["useful_expanded_ciphertexts"],
                                          m["other_dim_count"],
                                          m["expansion_height"]))
        chosen_h = selected[level - 1] if level - 1 < len(selected) else None
        for m in rows:
            role = []
            if m is legacy:
                role.append("legacy")
                legacy_sum += m["median_server_ms"]
            if chosen_h is not None and m["expansion_height"] == chosen_h:
                role.append("selected")
                selected_sum += m["median_server_ms"]
            if m.get("dominated"):
                role.append("dominated")
            print(f"{level:5d} {m['expansion_height']:2d} {m['first_dim_size']:4d} "
                  f"{m['other_dim_size']:6d} {m['padded_plaintexts']:7d} "
                  f"{m['expansion_substitutions']:5d} {m['inverse_ntts']:5d} "
                  f"{m['cmux_count']:5d} {m['median_server_ms']:10.3f}  "
                  f"{','.join(role)}")
    print()
    if legacy_sum > 0:
        print(f"predicted PIR-level server ms: legacy {legacy_sum:.2f} -> "
              f"selected {selected_sum:.2f} "
              f"({100.0 * (legacy_sum - selected_sum) / legacy_sum:+.2f}% gain)")
    # Attribution: where do the selected layouts differ from legacy?
    for level in sorted(by_level):
        rows = by_level[level]
        legacy = min(rows, key=lambda m: (m["padded_plaintexts"],
                                          m["useful_expanded_ciphertexts"],
                                          m["other_dim_count"],
                                          m["expansion_height"]))
        chosen_h = selected[level - 1] if level - 1 < len(selected) else None
        chosen = next((m for m in rows if m["expansion_height"] == chosen_h), None)
        if chosen is None or chosen is legacy:
            continue
        print(f"level {level}: h {legacy['expansion_height']}->{chosen['expansion_height']}: "
              f"candidates {legacy['other_dim_size']}->{chosen['other_dim_size']}, "
              f"INTT {legacy['inverse_ntts']}->{chosen['inverse_ntts']}, "
              f"CMux {legacy['cmux_count']}->{chosen['cmux_count']}, "
              f"expansion substitutions {legacy['expansion_substitutions']}->"
              f"{chosen['expansion_substitutions']}, padded +"
              f"{chosen['padded_plaintexts'] - legacy['padded_plaintexts']} pt, "
              f"median {legacy['median_server_ms']:.3f}->{chosen['median_server_ms']:.3f} ms")


def layerwise_case(report):
    for case in report["cases"]:
        if case["name"].startswith("merkle_layerwise"):
            return case
    raise SystemExit("no merkle_layerwise case in report")


def summarize_ab(legacy_path, profiled_path):
    a = layerwise_case(load(legacy_path))
    b = layerwise_case(load(profiled_path))
    print()
    print("A/B layerwise (legacy vs profiled):")
    for label, case in (("legacy", a), ("profiled", b)):
        samples = case["server_compute_samples_ms"]
        padded = sum(l["num_pt"] for l in case.get("layers", []))
        print(f"  {label:8}: mean {case['server_compute_ms']:.2f} ms, median "
              f"{statistics.median(samples):.2f} ms, n={len(samples)}, policy "
              f"{case.get('layer_layout_policy', '-')}, padded pt {padded}, "
              f"online bytes {case['online_total_bytes_mixed']}, "
              f"correct={case['correctness_passed']}")
        phases = case.get("server_phase_ms", {})
        if phases:
            print("            phases: " + ", ".join(
                f"{k} {v:.1f}" for k, v in sorted(phases.items())))
        pipe = case.get("pipeline_profile_ms", {})
        if pipe:
            print("            pipeline: " + ", ".join(
                f"{k} {v:.1f}" for k, v in sorted(pipe.items())))
    ma = statistics.median(a["server_compute_samples_ms"])
    mb = statistics.median(b["server_compute_samples_ms"])
    print(f"  median gain {100.0 * (ma - mb) / ma:+.2f}%, mean gain "
          f"{100.0 * (a['server_compute_ms'] - b['server_compute_ms']) / a['server_compute_ms']:+.2f}%")
    print(f"  communication unchanged: {a['online_total_bytes_mixed'] == b['online_total_bytes_mixed']}")
    la = {l["level"]: l for l in a.get("layers", [])}
    lb = {l["level"]: l for l in b.get("layers", [])}
    for level in sorted(la):
        if level in lb and la[level]["expansion_height"] != lb[level]["expansion_height"]:
            print(f"  level {level}: h {la[level]['expansion_height']}->"
                  f"{lb[level]['expansion_height']}, num_pt {la[level]['num_pt']}->"
                  f"{lb[level]['num_pt']}, cmux {la[level]['cmux_count']}->"
                  f"{lb[level]['cmux_count']}")


def main(argv):
    if len(argv) not in (2, 4):
        print(__doc__)
        return 2
    summarize_profile(load(argv[1]))
    if len(argv) == 4:
        summarize_ab(argv[2], argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
