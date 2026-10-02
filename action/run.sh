#!/usr/bin/env bash
# Runs quantum-safe-audit for the GitHub Action in ../action.yml.
# All inputs arrive as QS_* environment variables, never interpolated into this script, so a pull
# request cannot inject shell through an input value. Always exits 0 unless the inputs are invalid;
# the scan's own exit code is published as the `exit-code` output and enforced by a later step so that
# SARIF upload can still run when the gate fails.
set -uo pipefail

fail_usage() { echo "::error title=quantum-safe-audit::$1"; exit 2; }

path="${QS_PATH:-.}"
fail_on="${QS_FAIL_ON:-high}"
format="${QS_FORMAT:-sarif}"
output="${QS_OUTPUT:-quantum-safe-audit.sarif}"
version="${QS_VERSION:-latest}"
cbom="${QS_CBOM:-false}"
cnsa2="${QS_CNSA2:-false}"
policy="${QS_POLICY:-}"
exclude="${QS_EXCLUDE:-}"
allow_incomplete="${QS_ALLOW_INCOMPLETE:-false}"
inline_ignores="${QS_INLINE_IGNORES:-false}"
package_path="${QS_PACKAGE_PATH:-}"
out_file="${GITHUB_OUTPUT:-/dev/stdout}"
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"

case "$fail_on" in critical|high|medium|low|info|none) ;; *) fail_usage "fail-on must be one of critical, high, medium, low, info, none." ;; esac
case "$format" in text|json|sarif|cbom) ;; *) fail_usage "format must be one of text, json, sarif, cbom." ;; esac
[[ "$version" =~ ^(latest|[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?)$ ]] || fail_usage "version must be 'latest' or a semantic version."
[[ "$output" != /* && "$output" != *..* && "$output" != -* ]] || fail_usage "output must be a relative path inside the workspace."
[[ "$path" != /* && "$path" != *..* && "$path" != -* ]] || fail_usage "path must be relative to the workspace, must not contain '..' and must not start with '-'."
[[ "$policy" != -* ]] || fail_usage "policy must not start with '-'."
# Free-text inputs end up in file names, summaries and the outputs file: no control characters (newlines would let an input forge extra output lines).
for v in "$path" "$output" "$policy" "$version" "$fail_on" "$format"; do
  [[ ! "$v" =~ [[:cntrl:]] ]] || fail_usage "inputs must not contain control characters."
done

if [[ -n "$package_path" ]]; then
  cli=(node "$package_path/dist/cli.js")
else
  # Install the scanner OUTSIDE the scanned workspace and run it by absolute path. `npx` inside the workspace would resolve a
  # node_modules/quantum-safe-audit committed by a pull request (and honour its .npmrc) instead of the real package.
  tool="$(mktemp -d)"
  ( cd "$tool" && npm init -y >/dev/null 2>&1 \
    && NPM_CONFIG_USERCONFIG=/dev/null npm install --ignore-scripts --no-audit --no-fund --registry https://registry.npmjs.org/ "quantum-safe-audit@${version}" >/dev/null 2>&1 ) \
    || fail_usage "could not install quantum-safe-audit@${version} from the npm registry."
  cli=(node "$tool/node_modules/quantum-safe-audit/dist/cli.js")
fi

# The scanned tree must not be able to rewrite its own gate: ./.qs-audit.json is NOT auto-loaded. Pass `policy:` (from a trusted ref) to use one.
common=(--fail-on "$fail_on" --no-config)
[[ "$cnsa2" == "true" ]] && common+=(--cnsa2)
[[ "$allow_incomplete" == "true" ]] && common+=(--allow-incomplete)
# The scanned code must not be able to silence its own findings with inline comments unless you opt in.
[[ "$inline_ignores" == "true" ]] || common+=(--no-inline-ignore)
[[ -n "$policy" ]] && common+=(--policy "$policy")
while IFS= read -r line; do
  line="${line%$'\r'}"
  [[ -n "$line" ]] && common+=(--exclude "$line")
done <<< "$exclude"

mkdir -p "$(dirname "$output")"
"${cli[@]}" scan "$path" "${common[@]}" --format "$format" --output "$output"
code=$?

# A second, machine-readable pass for the outputs and the job summary (the scan is fast and deterministic).
json_tmp="$(mktemp)"
"${cli[@]}" scan "$path" "${common[@]}" --fail-on none --allow-incomplete --format json --output "$json_tmp" >/dev/null 2>&1
findings="unknown"; files="unknown"; sev=""
if [[ -s "$json_tmp" ]]; then
  counts="$(node -e '
    const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const by = r.summary || {};
    process.stdout.write([r.findings.length, r.filesScanned, ["critical","high","medium","low","info"].map(k => k + ":" + (by[k] || 0)).join(" ")].join("|"));
  ' "$json_tmp" 2>/dev/null)" && {
    findings="${counts%%|*}"; rest="${counts#*|}"; files="${rest%%|*}"; sev="${rest#*|}"
  }
fi
rm -f "$json_tmp"

cbom_note=""
if [[ "$cbom" == "true" ]]; then
  if "${cli[@]}" cbom "$path" "${common[@]}" --output quantum-safe-cbom.json >/dev/null 2>&1; then
    echo "cbom-file=quantum-safe-cbom.json" >> "$out_file"
  else
    cbom_note=" The CBOM could not be written."
    echo "::warning title=quantum-safe-audit::The CBOM could not be written."
  fi
fi

{
  echo "exit-code=$code"
  echo "report-file=$output"
  echo "findings=$findings"
} >> "$out_file" || { echo "::error title=quantum-safe-audit::could not write the step outputs."; exit 70; }

{
  echo "### Quantum-safe audit"
  echo
  if [[ "$code" -eq 2 ]]; then
    echo "The scan was **incomplete or failed** (exit 2): files were skipped or could not be analysed, nothing was scanned, or the tool could not run. This is not a clean result.${cbom_note}"
  else
    echo "Scanned ${files} files, ${findings} findings (${sev}).${cbom_note}"
  fi
  echo
  echo "This is an inventory of the cryptography the source names, not a compliance verdict. An empty result is not proof of absence."
} >> "$summary_file"

if [[ "$code" -eq 2 ]]; then
  echo "::error title=quantum-safe-audit::The scan was incomplete or failed (files skipped, nothing scanned, or an I/O error)."
elif [[ "$code" -eq 1 ]]; then
  echo "::warning title=quantum-safe-audit::Findings at or above '${fail_on}' were reported (${findings} total)."
fi
exit 0
