# common

Shared, **pure-JVM** IPC layer for the Screenmate CAN system — the mission-critical parse +
authentication path, extracted so it is unit-testable off-device and shared by the consumer SDK
instead of hand-inlined.

## Contents

- **`BatchCodec`** — encode/decode for the vendor-signal broadcast batch. Wire **v3** is frozen
  (see `docs/PROTOCOL.md` in the parent repo): `int version, long seq, long tsElapsed, int flags,
  int count, count×{int id, byte kind, int bits}`, followed by an 8-byte HMAC-SHA256 trailer over
  all preceding bytes. All integers are big-endian. `BatchCodecTest` pins the exact byte layout so a
  producer/consumer divergence is caught by a test, not on-car. (The pure-Java producer `agent`
  can't depend on this and mirrors the layout by hand — the test guards both.)
- **`Kind`** — VHAL value-kind tags (`INT32`, `FLOAT`, `BOOL`, `STRING`, `INT32_VEC`, `INT64`,
  `UNKNOWN`) used by the `VendorSignals` catalog. The live transport carries only `INT32`/`FLOAT`.

Imported by both **`agent`** (producer) and **`privileged-client`** (consumer SDK).

## Build

Android library module. Requirements: **JDK 17**, Android SDK **platform 34**, Gradle **8.9**
(Android Gradle Plugin 8.5.2, Kotlin 1.9.24). `minSdk` 29, `compileSdk` 34.

```bash
./gradlew :common:assembleRelease   # AAR
./gradlew :common:test              # run BatchCodecTest on the JVM
```

## Note

Extracted from a multi-module monorepo; this repo ships the module only (no Gradle wrapper / root
build). To build, place it under a settings.gradle(.kts) that `include(":common")` with the plugin
versions above, or add the wrapper and a root `build.gradle.kts` declaring them.
