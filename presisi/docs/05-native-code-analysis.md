# Native Code Analysis

Author: Kenshin Himura - DTrust

## Overview

The APK contains three native libraries across four Android architectures. The native code footprint is small compared with the DEX codebase.

## Libraries

| Library | Role |
|---|---|
| `libuptodown-native.so` | Custom Uptodown JNI library with API key retrieval functions |
| `libandroidx.graphics.path.so` | AndroidX graphics support library |
| `libdatastore_shared_counter.so` | AndroidX DataStore support library |

## Architectures

```text
arm64-v8a
armeabi-v7a
x86
x86_64
```

## JNI functions of interest

```text
Java_com_uptodown_util_NativeApiKey_getAuthApikey
Java_com_uptodown_util_NativeApiKey_getAuthApikeyLite
```

## Assessment

The reviewed native libraries did not show a native-code backdoor pattern, direct network handling, or root and debug detection logic in the extracted native report set. The custom native library appears to support API key retrieval through JNI.

The main analysis surface remains the DEX code, Android components, network endpoints, local storage, and telemetry-related workflows.
