# VH-Log (C)

C11 library with a request-scoped context; json-c and libsodium.

Implements this repository’s [interop profile](../../docs/profile.md),
including deterministic creation and updates, pre-rotation, witnesses,
version selection, partial validity, watcher copies, and fork detection.
Protocol logic runs in C; it does not call another implementation.

## Setup

```sh
# macOS
brew install json-c libsodium
# Debian/Ubuntu
sudo apt-get install build-essential libjson-c-dev libsodium-dev
sh build.sh
```

## Library usage

The public API in `src/vh_log.h` accepts the operations documented in the
[interop protocol](../../docs/interop-protocol.md). Each context owns its
allocations; returned JSON remains valid until `vh_context_free`.
Independent contexts can be used concurrently. Initialize libsodium once
before calling the library.

```c
#include "vh_log.h"
#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) return 1;
    vh_context *context = vh_context_new();
    json_object *response = vh_request(context,
        "{\"id\":1,\"op\":\"hash\",\"input\":{\"data\":\"hello\"}}");
    puts(json_object_to_json_string(response));
    vh_context_free(context);
}
```

Link `src/vh_log.c` with `-ljson-c -lsodium -lm`. The driver releases a
context after every request. Protocol failures return `ok: false`; invalid
logs return `ok: true` with `result.valid: false`.

## Verification and driver

From the repository root:

```sh
node harness/run.ts --impl c --impl typescript
VH_TEST_IMPLS=c node --test harness/driver-regressions.test.ts
```

The shared harness checks primitives, resolution, generation, external
reference logs, and cross-resolution. Boundary tests additionally check
binary64 formatting, Unicode, malformed-request recovery, LF framing,
and the supported calendar endpoints.

From this directory, start the JSON Lines driver with:

```sh
bin/vh-log-driver
```

See the [driver protocol](../../docs/interop-protocol.md) for request and
response shapes. Logs and witness files are supplied by the caller; the
resolver does not fetch network resources.
