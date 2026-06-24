.PHONY: build test fmt clean fitness fitness-latency fitness-recall-precision fitness-seam check

# ── build / test / fmt / clean (unchanged from v0) ─────────────────────────
build:
	go build -o bin/memory-guard ./...

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin

# ── fitness-function runner (task 012) ─────────────────────────────────────
#
# Three enforced gates (all block-severity):
#   fitness-latency          — per-op detect cost < 1 ms (REQ-003 / F-001 latency)
#   fitness-recall-precision — write-gate + PII recall/precision floors (REQ-004 / F-006)
#   fitness-seam             — no detector/store backend specifics in guard/ipc/main/contract (REQ-005 / F-004)
#
# `make fitness` runs all three and exits non-zero if any fail.
# `make check`   runs build + test + fitness (the full verification gate).
#
# Synthetic breach paths (to prove each gate goes red):
#   MEMGUARD_FITNESS_LATENCY_BREACH=1           make fitness-latency
#   MEMGUARD_FITNESS_RECALL_BREACH=1            make fitness-recall-precision
#   MEMGUARD_FITNESS_SEAM_BREACH=PresidioClient make fitness-seam

fitness-latency:
	go test -tags fitness -run TestFitnessLatency ./...

fitness-recall-precision:
	go test -tags fitness -run TestFitnessRecallPrecision ./...

fitness-seam:
	go test -tags fitness -run TestFitnessSeam ./...

fitness: fitness-latency fitness-recall-precision fitness-seam
	@echo "All fitness checks passed."

# ── check: the full verification gate ──────────────────────────────────────
check:
	go build ./...
	go test ./...
	$(MAKE) fitness
