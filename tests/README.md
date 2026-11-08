# 6.104.5 local verification

This is a pinned, local check of build 2494 arm64-v8a/xxxhdpi, not a device test. `Verify61045` uses the installed JADX dexlib and cached Android apksig; no dependency is downloaded. It checks the XAPK and split hashes/signers, DEX integrity and method shapes, callers, decoded instructions and branches, output signatures, bounded v010/v002/v015 profile semantics and ZIP payloads. `verify_energy.py` models 5,120 synthetic-constructor inputs from fresh JADX fallback output. Do not run Python with `-O`: its assertions are the test.

## Reproduce (from `my-patches/`)

```sh
set -eu
ROOT="$PWD"
INPUT=/tmp/duolingo-61045-research.S4kbyV/extracted
XAPK=/tmp/duolingo-61045-research.S4kbyV/duolingo-6.104.5-2494-arm64.xapk
RUN=$(mktemp -d /tmp/duolingo-61045-verify.XXXXXX)
JAVA17="$HOME/.sdkman/candidates/java/17.0.15-tem"
CLI=/tmp/reseam-0391.FYayP0/source/target/release/reseam
DEXLIB=/opt/homebrew/Cellar/jadx/1.5.6/libexec/lib/jadx-1.5.6-all.jar
APKSIG="$HOME/.gradle/caches/modules-2/files-2.1/com.android.tools.build/apksig/9.4.1/4b5fb2950c949258167c18b868e66d7a6f49ec3a/apksig-9.4.1.jar"
CP="$RUN:$DEXLIB:$APKSIG"
APKKEY="$ROOT/../patched/reseam.pk8"
APKCERT="$ROOT/../patched/reseam.der"
PUB=ad1ecee86cfe34a5449036141d8aaef54cfaf370bea845234096bc588a61367e
BUNDLE="$ROOT/build/reseam/duolingo-patches.reseam"
"$JAVA17/bin/javac" -cp "$DEXLIB:$APKSIG" -d "$RUN" tests/Verify61045.java
"$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 preflight "$XAPK" "$INPUT"
JAVA_HOME="$JAVA17" ANDROID_HOME="$HOME/Library/Android/sdk" \
  RESEAM_BUNDLE_KEY="$HOME/.reseam/bundle-signing.key" RESEAM_BIN="$CLI" ./gradlew --no-daemon bundle -PreleaseTag=v0.1.1
"$CLI" bundle list "$BUNDLE" --trust "$PUB" --verbose
"$CLI" patch "$INPUT/com.duolingo.apk" --split "$INPUT/config.arm64_v8a.apk" \
  --split "$INPUT/config.xxxhdpi.apk" --bundle "$BUNDLE" --trust "$PUB" --preset none \
  --enable app.example.patches.energyPatch --enable app.example.patches.interstitialPatch \
  --key "$APKKEY" --cert "$APKCERT" --output-dir "$RUN/patched"
"$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 raw "$INPUT/com.duolingo.apk" "$RUN/patched/com.duolingo.apk"
"$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 profiles "$INPUT/com.duolingo.apk" "$RUN/patched/com.duolingo.apk"
"$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 output "$INPUT" "$RUN/patched" "$APKCERT"
```

Run the model and negative checks:

```sh
JAVA_HOME="$HOME/.sdkman/candidates/java/21.0.6-amzn" jadx -r -m fallback \
  --single-class com.duolingo.core.energy.models.EnergyConfig \
  --single-class-output "$RUN/EnergyConfig.original.java" "$INPUT/com.duolingo.apk"
JAVA_HOME="$HOME/.sdkman/candidates/java/21.0.6-amzn" jadx -r -m fallback \
  --single-class com.duolingo.core.energy.models.EnergyConfig \
  --single-class-output "$RUN/EnergyConfig.patched.java" "$RUN/patched/com.duolingo.apk"
python3 tests/verify_energy.py "$RUN/EnergyConfig.original.java" "$RUN/EnergyConfig.patched.java"
for kind in energy-mask interstitial-registers; do
  "$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 mutate "$INPUT/com.duolingo.apk" "$kind" "$RUN/$kind.apk"
  if [ "$kind" = energy-mask ]; then patch=energyPatch; line='EnergyPatch.kt:53'; else patch=interstitialPatch; line='InterstitialPatch.kt:17'; fi
  if "$CLI" patch "$RUN/$kind.apk" --bundle "$BUNDLE" --trust "$PUB" --preset none \
    --enable "app.example.patches.$patch" --key "$APKKEY" --cert "$APKCERT" \
    --output "$RUN/$kind-output.apk" >"$RUN/$kind.log" 2>&1; then echo 'unexpected success'; exit 1; fi
  grep -F "$line" "$RUN/$kind.log"
  test ! -e "$RUN/$kind-output.apk"
done
"$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 mutate "$RUN/patched/com.duolingo.apk" energy-branch "$RUN/energy-branch.apk"
if "$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 raw "$INPUT/com.duolingo.apk" "$RUN/energy-branch.apk" >"$RUN/energy-branch.log" 2>&1; then echo 'unexpected success'; exit 1; fi
grep -F 'ordinary branch/instruction mismatch' "$RUN/energy-branch.log"
```

`mutate` refuses an existing destination and repairs DEX SHA-1/Adler32, but the resulting fixture is deliberately unsigned/invalidly signed and must not be installed. The guard tests execute the patch, and require the indicated failing guard and no output. Only create output in a new directory. No original/key is changed. To independently derive the publisher public key without displaying private key bytes (OpenSSL Ed25519 PKCS#8 seed header):

```sh
(printf '302e020100300506032b657004220420' | xxd -r -p; cat "$HOME/.reseam/bundle-signing.key") | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64
```

## Six profile negative tests

Create a fresh fixture directory; these mutations are unsigned and must never be installed. Each must fail for the specified reason, not merely fail arbitrarily:

```sh
for spec in 'profile-container|profile section bounds' 'profile-checksum|profile DEX CRC32' \
  'profile-identity|embedded profile method identity mismatch' 'profile-flags|embedded profile method flags mismatch' \
  'profile-mapping|metadata class mapping' 'profile-key|installed DEX key'; do
  kind=${spec%%|*}; reason=${spec#*|}
  "$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 mutate "$RUN/patched/com.duolingo.apk" "$kind" "$RUN/$kind.apk"
  if "$JAVA17/bin/java" -Xmx3g -cp "$CP" Verify61045 profiles "$INPUT/com.duolingo.apk" "$RUN/$kind.apk" >"$RUN/$kind.log" 2>&1; then echo 'unexpected success'; exit 1; fi
  grep -F "$reason" "$RUN/$kind.log"
done
```

## Rerun the existing outputs and fixtures (no build or signing)

The paths below are distinct: `INPUT` contains the original splits, `PATCHED` contains the signed output splits, and `FIX` contains the compiled verifier and six deliberately invalid unsigned fixtures. These commands work from any directory while the temporary files remain present.

```sh
set -eu
export JAVA_HOME="$HOME/.sdkman/candidates/java/17.0.15-tem"
DEXLIB=/opt/homebrew/Cellar/jadx/1.5.6/libexec/lib/jadx-1.5.6-all.jar
APKSIG="$HOME/.gradle/caches/modules-2/files-2.1/com.android.tools.build/apksig/9.4.1/4b5fb2950c949258167c18b868e66d7a6f49ec3a/apksig-9.4.1.jar"
FIX=/tmp/duolingo-61045-profile.qfHn5A
INPUT=/tmp/duolingo-61045-research.S4kbyV/extracted
PATCHED=/tmp/duolingo-61045-verify.Q3gySy/patched
CERT=/Users/thomaseeckhout/Code/duolingo/patched/reseam.der
CP="$FIX:$DEXLIB:$APKSIG"
"$JAVA_HOME/bin/java" -Xmx4g -cp "$CP" Verify61045 profiles "$INPUT/com.duolingo.apk" "$PATCHED/com.duolingo.apk"
"$JAVA_HOME/bin/java" -Xmx4g -cp "$CP" Verify61045 output "$INPUT" "$PATCHED" "$CERT"
for spec in 'profile-container|profile section bounds' 'profile-checksum|profile DEX CRC32' \
  'profile-identity|embedded profile method identity mismatch' 'profile-flags|embedded profile method flags mismatch' \
  'profile-mapping|metadata class mapping' 'profile-key|installed DEX key'; do
  kind=${spec%%|*}; reason=${spec#*|}
  if result=$("$JAVA_HOME/bin/java" -Xmx4g -cp "$CP" Verify61045 profiles "$INPUT/com.duolingo.apk" "$FIX/$kind.apk" 2>&1); then
    echo "unexpected success: $kind"; exit 1
  fi
  printf '%s\n' "$result" | grep -F "$reason"
done
```

The six existing fixture paths are `$FIX/profile-container.apk`, `$FIX/profile-checksum.apk`, `$FIX/profile-identity.apk`, `$FIX/profile-flags.apk`, `$FIX/profile-mapping.apk`, and `$FIX/profile-key.apk`. They are negative fixtures, not installable outputs.

## 0.39.1 results

Bundle: `build/reseam/duolingo-patches.reseam`, SHA-256 `9a60f6679046fdd908f093d92daa2ebfce8e725c0ff4e67f0591773abc09ca18`. Trusted catalog reports engine 0.39.1, version 0.1.1, the same publisher and exactly two patches. Fresh signed splits, logs and new negative fixtures: `/tmp/duolingo-61045-0391.UM1tZi/`. Preflight, raw checks on both old and new output, profiles, complete output verification, 5,120-case model, three guard/branch negatives and six profile negatives passed. Old/new fallback EnergyConfig and f7l output is identical. Wrong-trust patching and tampered-payload patching were rejected; catalog listing alone did not detect the payload tamper, so do not treat listing as payload validation. Kotlin LSP lacked the Reseam and standard library classpath; Gradle compilation succeeded.

The official release offers Linux/Windows binaries but no macOS binary or release assets/checksums. The local macOS CLI was built separately from official tag v0.39.1 commit `a47961c6261a7cf61b56d11dbb0b22efd643310e` using the pinned Rust 1.98.1 and BoltFFI 0.31.0, at `/tmp/reseam-0391.FYayP0/source/target/release/reseam`; the 0.28.0 CLI was not replaced. Paths under `/tmp` are ephemeral. Phone behavior and update acceptance remain untested.

## Historical 0.28.0 results

Initial split patch run and signed outputs: `/tmp/duolingo-61045-verify.Q3gySy/`. Amendment verifier, profile fixtures and logs: `/tmp/duolingo-61045-profile.qfHn5A/`. Bundle SHA-256: `ec747882a0718660f7366e3d6d3e18941a4f7ec3f890997db4656a4236b541ad`.

Preflight, trusted two-patch bundle listing, three output signatures, raw DEX, independent profiles and strict output checks **PASS**. Profile checks compare nine referenced DEX and 66,340 method identities/flags across original v010/v002, patched v010/v002 and patched v015; the 10 root DEX entries and one nested `assets/audience_network/classes.dex` in each base APK pass integrity checks (11 total per APK). Nine of the root DEX entries are profile-referenced. The remaining 18,234 base and 171 split non-signing payloads are byte-identical. Only the two DEX entries and three individually verified profile paths differ as approved. The 5,120-case model and all three original guard/branch negatives pass. All six profile negatives fail for their indicated reasons. Wrong-trust patching and a tampered bundle are rejected. Note that listing with a wrong trust key returns success but labels the signer **untrusted**.

The v010 profile is regenerated with DEX CRC32 values; v002 metadata and v015 embedded profile are validated against dexlib identities and original semantics. These checks do not establish ART runtime behavior, ad removal or unlimited lessons. Phone acceptance, release and update tests remain pending. Java LSP did not answer; Python LSP was clean. Kotlin LSP has unresolved Reseam/stdlib classpath references despite the successful Gradle build.
