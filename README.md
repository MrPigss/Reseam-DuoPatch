# Duolingo patches (experimental)

This unpublished bundle targets Duolingo **6.104.5** only:

- `app.example.patches.energyPatch`: sets constructor current energy to 25.
- `app.example.patches.interstitialPatch`: disables one automatic interstitial readiness decision.

Compatibility metadata checks the version name, not build code or ABI. The original inspected variant is build 2494, arm64-v8a/xxxhdpi, with base, ABI and density APKs. Neither change proves device behavior: lesson limits and ads require phone testing.

## Build and verification

Use JDK 17, Android SDK, and Reseam CLI and Gradle plugin 0.28.0. The existing publisher key is `~/.reseam/bundle-signing.key`; keep it private and back it up securely. Build with `RESEAM_BUNDLE_KEY` pointing to it and `./gradlew --no-daemon bundle -PreleaseTag=v0.1.0`. The expected public signer is `ad1ecee86cfe34a5449036141d8aaef54cfaf370bea845234096bc588a61367e`. Verify it before trusting a bundle.

The pinned complete split set was patched and signed. Local signatures, raw DEX, independently parsed baseline profiles, other payloads, the bounded energy model and negative tests passed under the approved profile amendment. See [tests/README.md](tests/README.md) for results and reproduction. This does not establish device behavior: phone acceptance, release access and update testing remain pending.

## Release and phone steps

Repository: https://github.com/MrPigss/Reseam-DuoPatch

The patch source is unavailable until the first release is published:
- Index: https://github.com/MrPigss/Reseam-DuoPatch/releases/latest/download/patches.json
- [Add to Reseam Manager](https://reseam.app/add/?url=https%3A%2F%2Fgithub.com%2FMrPigss%2FReseam-DuoPatch%2Freleases%2Flatest%2Fdownload%2Fpatches.json)

After completing local verification, audit tracked files for secrets and binaries. Set `BUNDLE_SIGNING_KEY_B64` privately to the base64-encoded **same** publisher key (base64 is not encryption). The existing tag-triggered workflow can publish the bundle and `patches.json`. Compare its public key with the key above before trusting it in Manager. Test installation, lesson limits, ads, login, results, restart and sync on the phone, noting subscription status; test updates separately.

The bundle publisher key and APK signing key are different identities. A store-signed installation normally cannot be replaced by a differently signed APK, and Manager may use a different APK identity from the CLI. Sync progress and understand local-data loss before any uninstall; never uninstall automatically.

## License

AGPL-3.0-or-later, with additional terms under section 7 in [NOTICE](NOTICE).
