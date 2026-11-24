# Native Debian / Alpine package version comparison

`collector/vendor_version_check.py` performs an **opt-in host-side** comparison of an explicitly supplied installed package version against a vendor-provided fixed version.

Debian uses `dpkg --compare-versions INSTALLED ge FIXED` and Alpine uses `apk version -t INSTALLED FIXED`. This avoids naive lexical ordering and supports distro-specific epochs and revision syntax where the installed native tool supports it.

## Usage

```sh
cd poc/vire
python3 collector/vendor_version_check.py --distro debian --installed '1:3.0.17-1~deb12u1' --fixed '1:3.0.17-1~deb12u2'
python3 collector/vendor_version_check.py --distro alpine --installed '3.3.2-r0' --fixed '3.3.2-r1'
```

The commands require `dpkg` or `apk` on the trusted execution host respectively. Neither utility requires a paid subscription, API key or waAIf Cloud account. A future containerized implementation may use isolated distro-specific tools instead of installing both package managers on the host.

## Semantics and trust boundary

- `at_or_above_fixed_version`: native comparison is greater than or equal to the provided fixed version.
- `below_fixed_version`: native comparison is lower than the provided fixed version.
- `needs_verification`: utility missing, error, timeout or unexpected output.

**These are version-ordering results, not security verdicts.** VIRE must still authenticate the package inventory, ensure distro/release/source package match the advisory, verify the vendor feed and consider other applicable advisories. A patched version does not establish that the container image or runtime is otherwise secure.

The current utility is not automatically wired into the normalized advisory review; that integration requires verified installed-package provenance and a defined policy for multiple fixes. No automated remediation is permitted.

## Testing

```sh
cd poc/vire
python3 -m unittest discover -s collector -v -p 'test_*.py'
```

Tests mock native utilities; live dpkg/apk behavior must be separately checked on the appropriate distro environments.
