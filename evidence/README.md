# Preserved research evidence

The ZIP preserves evaluation directories at their original target/ paths, excluding the TLS/.env fixtures listed in MANIFEST.json. Originals remain unchanged locally. Extract into the repository root to restore reports, snapshots, frozen binaries and downloaded evaluation inputs. Ordinary compiler outputs are excluded. Downloaded repositories are evaluation inputs, not ARCHER source. Historical/frozen results do not describe every current engine revision; see research/peer-recall.md.

Archive SHA-256: `2f5c4f2bf689b94c018faaa1a153b70f1cc29e1a9f70f5e078c8d43fe45acd2b`

MANIFEST.json records the SHA-256 of every included file.

The root archer-graph.dot and archer-review.patch files are historical artifacts, not authoritative output of the current engine. External auth_actix and SeaORM input repositories must be supplied separately when reproducing their scans.
