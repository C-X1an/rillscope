# Third-party notices

RillScope first-party source and self-authored synthetic fixtures are MIT licensed. The resolved Rust graph below is from `cargo metadata --locked`; it includes platform-conditional and build dependencies. Production uses serde/serde_json for closed transport, sha2 for content identities, and Unix-only signal-hook for cooperative signals. The SQL frontend and executor are original Rust.

The shipped notice files preserve the selected MIT alternative for packages declaring MIT OR Apache-2.0. unicode-ident additionally requires its Unicode-3.0 notice. The declared expressions, selected licenses, exact versions and notice hashes are in [the inventory](licenses/dependency-inventory.json), bound to Cargo.lock. These declarations and a scanner result are evidence with a scope, not an exhaustive legal or vulnerability guarantee.

| Package | Version | Declared expression | Preserved notice |
|:--|:--|:--|:--|
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | [notice](licenses/block-buffer-0.10.4/LICENSE-MIT) |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | [notice](licenses/cfg-if-1.0.5/LICENSE-MIT) |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | [notice](licenses/cpufeatures-0.2.17/LICENSE-MIT) |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | [notice](licenses/crypto-common-0.1.7/LICENSE-MIT) |
| digest | 0.10.7 | MIT OR Apache-2.0 | [notice](licenses/digest-0.10.7/LICENSE-MIT) |
| errno | 0.3.14 | MIT OR Apache-2.0 | [notice](licenses/errno-0.3.14/LICENSE-MIT) |
| generic-array | 0.14.7 | MIT | [notice](licenses/generic-array-0.14.7/LICENSE) |
| itoa | 1.0.18 | MIT OR Apache-2.0 | [notice](licenses/itoa-1.0.18/LICENSE-MIT) |
| libc | 0.2.190 | MIT OR Apache-2.0 | [notice](licenses/libc-0.2.190/LICENSE-MIT) |
| memchr | 2.8.3 | Unlicense OR MIT | [notice](licenses/memchr-2.8.3/LICENSE-MIT) |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | [notice](licenses/proc-macro2-1.0.107/LICENSE-MIT) |
| quote | 1.0.47 | MIT OR Apache-2.0 | [notice](licenses/quote-1.0.47/LICENSE-MIT) |
| serde | 1.0.229 | MIT OR Apache-2.0 | [notice](licenses/serde-1.0.229/LICENSE-MIT) |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | [notice](licenses/serde_core-1.0.229/LICENSE-MIT) |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 | [notice](licenses/serde_derive-1.0.229/LICENSE-MIT) |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | [notice](licenses/serde_json-1.0.151/LICENSE-MIT) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | [notice](licenses/sha2-0.10.9/LICENSE-MIT) |
| signal-hook | 0.3.18 | Apache-2.0/MIT | [notice](licenses/signal-hook-0.3.18/LICENSE-MIT) |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 | [notice](licenses/signal-hook-registry-1.4.8/LICENSE-MIT) |
| syn | 3.0.9 | MIT OR Apache-2.0 | [notice](licenses/syn-3.0.9/LICENSE-MIT) |
| typenum | 1.20.1 | MIT OR Apache-2.0 | [notice](licenses/typenum-1.20.1/LICENSE-MIT) |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 | [notice](licenses/unicode-ident-1.0.27/LICENSE-MIT), [notice](licenses/unicode-ident-1.0.27/LICENSE-UNICODE) |
| version_check | 0.9.5 | MIT/Apache-2.0 | [notice](licenses/version_check-0.9.5/LICENSE-MIT) |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | [notice](licenses/windows-link-0.2.1/license-mit) |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | [notice](licenses/windows-sys-0.61.2/license-mit) |
| zmij | 1.0.23 | MIT | [notice](licenses/zmij-1.0.23/LICENSE-MIT) |

Python is an external test/report runtime under the PSF license; its standard-library SQLite baseline is not the product execution engine. SQLite authors dedicate SQLite to the public domain ([upstream notice](https://sqlite.org/copyright.html)). No third-party dataset, production/customer data or model API is used. Rust/compiler/OS and verification tools are external installations with their own notices, not vendored first-party source.
