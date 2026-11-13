# Repository source statistics

Production functionality is preserved; the size reduction comes from packaging exclusions. Build artifacts and Git internals are excluded from both source measurements. Original saved output text/binary evidence is counted in its own categories.

| Measure | Original working tree | Packaged backend |
| --- | ---: | ---: |
| Total files | 113 | 51 |
| Production Rust lines | 12,704 | 12,704 |
| src test/helper/legacy Rust lines | 7,395 | 7,395 |
| Total test/fixture/verification lines | 8,583 | 8,656 |
| Documentation/configuration lines | 11,912 | 6,675 |
| Operational script lines | 0 | 14 |
| Research evaluation script lines | 675 | 0 |
| Historical generated text lines | 38,763 | 0 |
| Total text/code lines | 72,637 | 28,049 |
| Binary files | 9 | 0 |
| Total bytes | 19,505,585 | 1,092,939 |
| Total decimal MB | 19.506 | 1.093 |

The source tree contains no historical evidence ZIP, generated graph screenshot, old analysis result, compiled binary or target cache. Newly generated acceptance graphs/results and compiled test binaries are preserved only in the separate verification directory.

Essential exceptions retained: the compile-time demo source, demo manifests/lockfile and optional reproduction script, graph test helpers, all original Rust tests and the test-only legacy prototype. Research-only reporting/evaluation suites are outside this deployable source edition. The exact per-file keep/replace/exclude decisions are in manifest.json.

The original working tree and uncommitted source are preserved. This package uses the original stronger implementation and retains RealWorld peer groups and informational analyses. See VERIFICATION.md and READINESS.md.
