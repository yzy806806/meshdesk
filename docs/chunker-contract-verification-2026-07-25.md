# Chunker Contract Verification — t_7ad60829

**Date:** 2026-07-25  
**HEAD:** a9b1ab5 (fix(harness): wire ssh_proxy capability for WebSSH integration tests)  
**Verifier:** architect  

## Scope

Verify the three reviewer-identified contract gaps from t_7ad60829 against HEAD:
1. **Total computation** — Does the Chunk struct carry Total, do Chunker implementations set it correctly, and does the Reassembler use it for completion detection?
2. **Overflow guard** — Is there protection against sequence number overflow or out-of-range chunks?
3. **Edge-case unit tests** — Are table-driven tests present for empty input, single chunk, boundary conditions, out-of-range sequences, etc.?

## Gap 1: Total Computation — RESOLVED

| Artifact | Status | Evidence |
|----------|--------|----------|
| `Chunk.Total uint32` field | Present | chunker.go:93 — documented as "0 means unknown (streaming mode)" |
| `fixedChunker.Split()` sets Total | Correct | chunker_fixed16k.go:78-80 — `if c.totalSet { chunk.Total = c.total }` |
| `boundedChunker.Split()` sets Total | Correct | chunker_bounded.go:128-130 — identical pattern |
| `SetTotal()` methods | Present | Both implementations have `SetTotal(uint32)` setting `c.totalSet = true` |
| Wire format includes Total | Correct | protocol.go:213,229 — `binary.BigEndian.PutUint32(plaintext[8:12], chunk.Total)` — inside AEAD ciphertext |
| `ExitReassembler.processChunk()` uses Total | Correct | exit_reassembler.go:247-261 — updates `st.total` from chunk metadata, checks `st.nextExpected >= st.total` for completion |
| Out-of-range sequence rejection | Correct | exit_reassembler.go:222-228 — rejects chunks with `chunk.Sequence >= chunk.Total` when Total is known |

## Gap 2: Overflow Guard — RESOLVED

| Condition | Status | Evidence |
|-----------|--------|----------|
| uint32 range (4B chunks ≈ 64TB at 16KB) | Accepted risk | Discussed and accepted for v1 — no circuit lives that long |
| Sequence >= Total rejection | Present | exit_reassembler.go:222-228 — out-of-range chunks silently ignored |
| `TestReassemblerTotalCompletionOutOfRangeSequences` | Present | chunker_test.go:288-314 — verifies chunks seq=5,6 don't trigger premature completion when Total=3 |
| `TestExitReassemblerTotalOutOfRangeSequences` | Present | exit_reassembler_test.go — exit-side equivalent |

## Gap 3: Edge-Case Unit Tests — RESOLVED

All tests below pass on HEAD:

| Test | Category | File |
|------|----------|------|
| `TestChunkerSplitEmpty` | Empty input → 0 chunks | chunker_test.go |
| `TestReassemblerSingleChunkStream` | Total=1 single chunk | chunker_test.go |
| `TestReassemblerTotalCompletion` | All 0..Total-1 → done | chunker_test.go |
| `TestReassemblerTotalCompletionOutOfRangeSequences` | Out-of-range gaps | chunker_test.go |
| `TestReassemblerStreamEndMarker` | Total=0 streaming + ChunkStreamEnd | chunker_test.go |
| `TestReassemblerInOrder` | In-order reassembly | chunker_test.go |
| `TestReassemblerOutOfOrder` | Out-of-order reassembly | chunker_test.go |
| `TestReassemblerDeduplication` | Duplicate (StreamID, Seq) ignored | chunker_test.go |
| `TestFingerprintChunkSizeBounds` | Sizes within [Min, Max] for 4 strategies | chunker_fingerprint_test.go |
| `TestFingerprintSmallPayloadProducesSingleChunk` | 5-byte input → 1 chunk | chunker_fingerprint_test.go |
| `TestFingerprintEmptyPayloadProducesNoChunks` | nil/empty → 0 chunks | chunker_fingerprint_test.go |
| `TestFingerprintNoSizeZeroChunks` | Never produce zero-size chunks | chunker_fingerprint_test.go |
| `TestFingerprintChunkSequencesAreMonotonic` | Sequences strictly increasing | chunker_fingerprint_test.go |
| `TestMetadataInCiphertextContract` | Total survives AEAD roundtrip | chunker_test.go |
| `TestReassemblerChunkBoundsEnforced` | MaxReassemblyChunks enforced | chunker_test.go |
| `TestReassemblerByteBoundsEnforced` | MaxReassemblyBytes enforced | chunker_test.go |
| `TestReassemblerByteBoundsCrossStream` | Multi-stream byte tracking | chunker_test.go |
| `TestPaddingSeedDeterministic` | Same seed → same padding | chunker_test.go |
| `TestPaddingSeedIsolation` | Different seeds → different padding | chunker_test.go |
| `TestReassemblerStreamIDIsolated` | Cross-stream isolation | chunker_test.go |

**Total tests passing:** 73+ (all Chunker/Reassembler/Fingerprint tests in `internal/proxy/`)

## Verdict

**t_7ad60829 is resolved.** All three reviewer-identified contract gaps are addressed in HEAD:

1. **Total field** is present in the `Chunk` struct, serialized in the AEAD-encrypted wire format, set by both Chunker implementations, and used by the ExitReassembler for both completion detection and out-of-range rejection.
2. **Overflow guard** is handled via the ExitReassembler's sequence range check (`chunk.Sequence >= chunk.Total` rejection) with the uint32 wrap-around scenario accepted as v1 risk.
3. **Edge-case tests** are comprehensive — empty input, single chunk, boundary conditions, out-of-range sequences, streaming mode (Total=0 + ChunkStreamEnd), deduplication, bounds enforcement, padding determinism, and multi-stream isolation. All pass.

The task can be closed.
