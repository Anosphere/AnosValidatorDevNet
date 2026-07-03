package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/core"
	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	// Optional manifest-driven config (B): -manifest points at a network manifest JSON
	// (e.g. config/testnet.json). When set it POPULATES the same env vars the tested env
	// path below reads (so the resulting EngineConfig is byte-identical), and derives
	// PEERS/PORT from the roster by locating this node via its consensus key. With no
	// -manifest the historical pure-env path runs completely unchanged.
	manifestPath := flag.String("manifest", "", "path to a network manifest JSON (config/testnet.json); populates config + derives PEERS/PORT from the roster")
	keyFlag := flag.String("key", "", "path to this validator's P-256 private key (overrides VALIDATOR_KEY_PATH)")
	dbFlag := flag.String("db", "", "path to the bbolt DB file (overrides DB_PATH)")
	portFlag := flag.String("port", "", "listen port (overrides PORT / the port derived from the manifest roster)")
	flag.Parse()
	if *keyFlag != "" {
		_ = os.Setenv("VALIDATOR_KEY_PATH", *keyFlag)
	}
	if *dbFlag != "" {
		_ = os.Setenv("DB_PATH", *dbFlag)
	}
	if *portFlag != "" {
		_ = os.Setenv("PORT", *portFlag)
	}
	// -manifest is MANDATORY (P7.2): the network manifest supplies every consensus scalar and the
	// network_id a node needs to peer. There is no env-only boot — a node with no manifest cannot
	// content-address itself and would be a fork risk.
	if *manifestPath == "" {
		log.Fatal("-manifest is required: it supplies the consensus scalars + network_id (see config/testnet.json)")
	}
	manifest, err := loadManifest(*manifestPath)
	if err != nil {
		log.Fatalf("manifest %q: %v", *manifestPath, err)
	}

	port := getenv("PORT", "8080")
	dbPath := getenv("DB_PATH", "validator.db")
	peers := splitCSV(getenv("PEERS", "")) // comma-separated base URLs
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	epochMS, perr := strconv.Atoi(mustEnv("EPOCH_MS"))
	if perr != nil || epochMS <= 0 {
		log.Fatal("EPOCH_MS must be a positive integer (milliseconds); it comes from the manifest")
	}

	genesisMs, _ := strconv.ParseInt(getenv("GENESIS_UNIX_MS", "0"), 10, 64)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required (milliseconds since unix epoch); must be identical on all validators")
	}

	var signer core.ValidatorSigner
	var selfID [33]byte

	keyPath := strings.TrimSpace(os.Getenv("VALIDATOR_KEY_PATH"))
	if keyPath == "" {
		log.Fatal("VALIDATOR_KEY_PATH is required (path to PEM or hex private key file)")
	}
	privECDSA, err := crypto.LoadP256PrivateKeyFromFile(keyPath)
	if err != nil {
		log.Fatalf("failed to load private key from %q: %v", keyPath, err)
	}
	selfID = crypto.CompressP256PublicKey(&privECDSA.PublicKey)
	signer = core.NewLocalP256Signer(privECDSA)

	fmt.Println("Validator Public Key:", hex.EncodeToString(selfID[:]))

	setCSV := strings.TrimSpace(os.Getenv("VALIDATOR_SET_PUBKEYS"))
	if setCSV == "" {
		log.Fatal("VALIDATOR_SET_PUBKEYS is required (csv of 33-byte compressed pubkeys hex)")
	}
	validatorSet, err := crypto.ParseValidatorSetCSV(setCSV)
	if err != nil {
		log.Fatalf("VALIDATOR_SET_PUBKEYS invalid: %v", err)
	}
	if _, ok := validatorSet[selfID]; !ok {
		log.Fatal("validator set does not include this validator's public key")
	}

	// VALIDATOR_IDENTITY_HEX (P4.3, working notes §3.7) is this node's Banker account-id — the
	// durable 32-byte PQ identity that staked Banker with this node's consensus key. OPTIONAL in
	// P4.3a: after the list→Fund flip the set is keyed by identity, so a node uses it to recognise
	// its own slot / a kick, but participation is still by consensus key, so an unset value only
	// disables that self-awareness (the env list anchors the flip via the consensus-key set). Becomes
	// required for a banker node once consensus is Fund-native.
	var selfIdentity [32]byte
	if idHex := strings.TrimSpace(os.Getenv("VALIDATOR_IDENTITY_HEX")); idHex != "" {
		idBytes, derr := hex.DecodeString(idHex)
		if derr != nil || len(idBytes) != 32 {
			log.Fatal("VALIDATOR_IDENTITY_HEX, if set, must decode to exactly 32 bytes")
		}
		copy(selfIdentity[:], idBytes)
		fmt.Println("Validator Banker identity:", idHex)
	}

	fundHex := strings.TrimSpace(os.Getenv("FUND_ACCOUNT_HEX"))
	if fundHex == "" {
		log.Fatal("FUND_ACCOUNT_HEX is required (32-byte hex public key)")
	}
	fundBytes, err := hex.DecodeString(fundHex)
	if err != nil || len(fundBytes) != 32 {
		log.Fatal("FUND_ACCOUNT_HEX must decode to exactly 32 bytes")
	}
	var fundAcct [32]byte
	copy(fundAcct[:], fundBytes)

	genHex := strings.TrimSpace(os.Getenv("GENESIS_HEX"))
	if genHex == "" {
		log.Fatal("GENESIS_HEX is required (32-byte hex public key)")
	}
	genBytes, err := hex.DecodeString(genHex)
	if err != nil || len(genBytes) != 32 {
		log.Fatal("GENESIS_HEX must decode to exactly 32 bytes")
	}
	var genesisAcct [32]byte
	copy(genesisAcct[:], genBytes)

	// GENESIS_AUTH_PUBKEY_HEX is the canonical 2625-byte hybrid auth pubkey of the
	// genesis account (keys-spec §5.2). Manifest-pinned because genesis is seeded
	// directly with no key-registering opening block (spec-18 §8); seeded into the
	// genesis AUTH_PUBKEY TLV so its hybrid-signed distribution SENDs verify. Must be
	// identical on all validators.
	genAuthHex := strings.TrimSpace(os.Getenv("GENESIS_AUTH_PUBKEY_HEX"))
	if genAuthHex == "" {
		log.Fatal("GENESIS_AUTH_PUBKEY_HEX is required (5250-hex-char / 2625-byte hybrid auth pubkey)")
	}
	genAuthPub, err := hex.DecodeString(genAuthHex)
	if err != nil || len(genAuthPub) != crypto.HybridPubKeySize {
		log.Fatalf("GENESIS_AUTH_PUBKEY_HEX must decode to exactly %d bytes", crypto.HybridPubKeySize)
	}

	genSupplyStr := strings.TrimSpace(os.Getenv("GENESIS_SUPPLY_UNITS"))
	if genSupplyStr == "" {
		log.Fatal("GENESIS_SUPPLY_UNITS is required (uint64)")
	}
	genSupply, err := strconv.ParseUint(genSupplyStr, 10, 64)
	if err != nil {
		log.Fatal("GENESIS_SUPPLY_UNITS must be uint64")
	}

	// TIMELOCKED_DELAY_EPOCHS is the minimum timelock (in epochs) for funds moving out of a
	// TIMELOCKED account through a transfer chain. CONSENSUS-CRITICAL: must be byte-identical
	// on every validator, exactly like EPOCH_MS / GENESIS_UNIX_MS. Default ~1 week (@5s epochs);
	// local test .env files set a small value (e.g. 12 ≈ 1 minute).
	timelockedDelayEpochs, err := strconv.ParseUint(mustEnv("TIMELOCKED_DELAY_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("TIMELOCKED_DELAY_EPOCHS must be a uint64 (number of epochs)")
	}
	fmt.Println("Timelocked transfer delay (epochs):", timelockedDelayEpochs)

	// GUARDIAN_ACTIVE_WINDOW_EPOCHS is the trailing window within which a Guardian counts toward
	// the ACTIVE set (the denominator M for the weighted Fund-SEND quorum, spec-19 §6.2).
	// CONSENSUS-CRITICAL: must be byte-identical on every validator, exactly like EPOCH_MS /
	// TIMELOCKED_DELAY_EPOCHS. Default ~5 weeks (@5s epochs ≈ 604800); local test .env files set
	// a small value (e.g. 20). P7's network manifest must content-address it.
	guardianActiveWindowEpochs, err := strconv.ParseUint(mustEnv("GUARDIAN_ACTIVE_WINDOW_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("GUARDIAN_ACTIVE_WINDOW_EPOCHS must be a uint64 (number of epochs)")
	}
	fmt.Println("Guardian active window (epochs):", guardianActiveWindowEpochs)

	// STAKE_LOCK_{1MO,1YR}_EPOCHS are the per-tier stake lock delays (P2.3b): a Guardian-returned
	// stake's TRANSFER chain cannot release before creation + the staked tier's lock. CONSENSUS-
	// CRITICAL: identical on every validator. Defaults ~1mo / ~1yr @5s epochs; local test .env files
	// set small values.
	stakeLock1mo, err := strconv.ParseUint(mustEnv("STAKE_LOCK_1MO_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("STAKE_LOCK_1MO_EPOCHS must be a uint64 (number of epochs)")
	}
	stakeLock1yr, err := strconv.ParseUint(mustEnv("STAKE_LOCK_1YR_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("STAKE_LOCK_1YR_EPOCHS must be a uint64 (number of epochs)")
	}
	fmt.Println("Stake lock (epochs) 1mo/1yr:", stakeLock1mo, stakeLock1yr)

	// GUARDED_DELAY_EPOCHS / VAULT_DELAY_EPOCHS are the per-class transfer delays for GUARDED /
	// VAULT sources (P3.2, spec-18 §6). CONSENSUS-CRITICAL: byte-identical on every validator,
	// exactly like TIMELOCKED_DELAY_EPOCHS. Defaults ~2 weeks / ~4 weeks @5s epochs (VAULT >
	// GUARDED > TIMELOCKED); local test .env files set small values. P7's manifest must pin them.
	guardedDelayEpochs, err := strconv.ParseUint(mustEnv("GUARDED_DELAY_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("GUARDED_DELAY_EPOCHS must be a uint64 (number of epochs)")
	}
	vaultDelayEpochs, err := strconv.ParseUint(mustEnv("VAULT_DELAY_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("VAULT_DELAY_EPOCHS must be a uint64 (number of epochs)")
	}
	fmt.Println("Guarded/Vault transfer delay (epochs):", guardedDelayEpochs, vaultDelayEpochs)

	// ATTESTOR_QUORUM_M is the flat M-of-N Fund Attestor quorum threshold gating GUARDED/VAULT (and
	// breakglass) releases (P3.2, spec-19 §6.1). CONSENSUS-CRITICAL manifest constant; MUST be >= 1
	// (a zero would make the attestor gate a no-op). Local test .env files set a small value (e.g. 2).
	attestorQuorumM, err := strconv.ParseUint(mustEnv("ATTESTOR_QUORUM_M"), 10, 64)
	if err != nil {
		log.Fatal("ATTESTOR_QUORUM_M must be a uint64 (number of attestor signatures)")
	}
	if attestorQuorumM < 1 {
		log.Fatal("ATTESTOR_QUORUM_M must be >= 1 (a zero would disable the attestor release gate)")
	}
	fmt.Println("Attestor quorum (flat M):", attestorQuorumM)

	// ESCROW_ATTESTATION_DELAY_EPOCHS is the minimum gap between an escrow's creation and its
	// attestation_trigger_epoch (P3.3, spec-18 §5.6.3) — the earliest the 1-of-2 → Fund trigger
	// (attested escrows only) may fire. CONSENSUS-CRITICAL: byte-identical on every validator, like
	// the other delays. Default ~1 week @5s epochs; local test .env files set a small value.
	escrowAttestationDelayEpochs, err := strconv.ParseUint(mustEnv("ESCROW_ATTESTATION_DELAY_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("ESCROW_ATTESTATION_DELAY_EPOCHS must be a uint64 (number of epochs)")
	}
	fmt.Println("Escrow attestation delay (epochs):", escrowAttestationDelayEpochs)

	// BREAKGLASS_EXTRA_EPOCHS is the +1-week fraud-challenge window added to a breakglass move's
	// transfer-chain unlock (P5.1, spec-18 §6, spec-19 §6.4), on top of the source class's normal
	// transfer delay. CONSENSUS-CRITICAL: byte-identical on every validator. Must be >= 1 so a
	// breakglass release is never immediate (a SPENDING source has zero class delay, so this window is
	// the whole lock). Default ~1 week @5s epochs; local test .env files set a small value.
	breakglassExtraEpochs, err := strconv.ParseUint(mustEnv("BREAKGLASS_EXTRA_EPOCHS"), 10, 64)
	if err != nil {
		log.Fatal("BREAKGLASS_EXTRA_EPOCHS must be a uint64 (number of epochs)")
	}
	if breakglassExtraEpochs < 1 {
		log.Fatal("BREAKGLASS_EXTRA_EPOCHS must be >= 1 (a zero would make a breakglass release immediate)")
	}
	fmt.Println("Breakglass extra delay (epochs):", breakglassExtraEpochs)

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Consensus economics (P7.2): read straight off the validated manifest struct so the validator
	// enforces exactly what network_id hashed — no code-side default. The Snapshot / EngineConfig
	// carry this and the role/fee derivations consume it (Economics.IsBanker / RequiredFee / ...).
	econ := core.Economics{
		MinFee:                           manifest.Economics.MinFee,
		MaxFee:                           manifest.Economics.MaxFee,
		AttestedEscrowFee:                manifest.Economics.AttestedEscrowFee,
		FeeBps:                           manifest.Economics.FeeBps,
		BankerStakeFloorAnos:             manifest.Economics.BankerStakeFloorAnos,
		AttestorStakeFloorAnos:           manifest.Economics.AttestorStakeFloorAnos,
		GuardianDivisorAnos:              manifest.Economics.GuardianDivisorAnos,
		GuardianSendThresholdBps:         manifest.Economics.GuardianSendThresholdBps,
		GuardianFundSendEpochSlackEpochs: manifest.Economics.GuardianFundSendEpochSlackEpochs,
	}
	fmt.Println("Network id:", manifest.NetworkID, "protocol_version:", manifest.ProtocolVersion)

	engine, err := core.NewEngine(core.EngineConfig{
		DB:                           db,
		Signer:                       signer,
		ValidatorSet:                 validatorSet,
		Peers:                        peers,
		GenesisUnixMs:                genesisMs,
		EpochDuration:                time.Duration(epochMS) * time.Millisecond,
		QuorumPercent:                manifest.Consensus.QuorumPercent,
		FinalizationQuorumPercent:    manifest.Consensus.FinalizationQuorumPercent,
		FinalizationSkew:             800 * time.Millisecond,
		CandidatesSkew:               800 * time.Millisecond,
		FundAccount:                  fundAcct,
		GenesisAccount:               genesisAcct,
		GenesisSupply:                genSupply,
		GenesisAuthPubKey:            genAuthPub,
		TimelockedDelayEpochs:        timelockedDelayEpochs,
		GuardianActiveWindowEpochs:   guardianActiveWindowEpochs,
		StakeLock1moEpochs:           stakeLock1mo,
		StakeLock1yrEpochs:           stakeLock1yr,
		GuardedDelayEpochs:           guardedDelayEpochs,
		VaultDelayEpochs:             vaultDelayEpochs,
		AttestorQuorumM:              attestorQuorumM,
		EscrowAttestationDelayEpochs: escrowAttestationDelayEpochs,
		BreakglassExtraEpochs:        breakglassExtraEpochs,
		Econ:                         econ,
		MaxCandidateScanPerSlot:      manifest.Consensus.MaxCandidateScanPerSlot,
		NetworkID:                    manifest.NetworkID,
		ProtocolVersion:              manifest.ProtocolVersion,
		SelfIdentity:                 selfIdentity,
	})

	if err != nil {
		log.Fatal(err)
	}

	engine.Start(ctx)

	mux := http.NewServeMux()

	// ---- Peer endpoints (protobuf-delimited streams) ----

	// GET /peer/id -> Pub32
	mux.HandleFunc("/peer/id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_ = writeProtoDelim(w, &pb.Pub32{V: selfID[:]})
	})

	// POST /peer/candidates
	// Body is a protobuf-delimited CandidateListV2 (proposer validator_id, epoch, list_hash,
	// SigDER over the list hash, and the txid votes).
	mux.HandleFunc("/peer/candidates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var cl pb.CandidateListV2
		if err := readProtoDelim(r.Body, &cl); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if cl.Proposer == nil || len(cl.Proposer.V) != 33 {
			http.Error(w, "bad proposer", 400)
			return
		}
		if cl.ListHash == nil || len(cl.ListHash.V) != 32 {
			http.Error(w, "bad list_hash", 400)
			return
		}
		if cl.Sig == nil || len(cl.Sig.V) < 64 || len(cl.Sig.V) > 80 {
			http.Error(w, "bad sig", 400)
			return
		}

		var vid [33]byte
		copy(vid[:], cl.Proposer.V)
		var lh [32]byte
		copy(lh[:], cl.ListHash.V)

		txids := make([][32]byte, 0, len(cl.Txid))
		for _, h := range cl.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var id [32]byte
			copy(id[:], h.V)
			txids = append(txids, id)
		}

		c := &core.CandidateList{
			Epoch:       cl.Epoch,
			ValidatorID: vid,
			ListHash:    lh,
			SigDER:      append([]byte(nil), cl.Sig.V...),
			TxIDs:       txids,
		}

		from := r.Header.Get("X-Validator-URL")
		if from == "" {
			from = r.RemoteAddr
		}
		if err := engine.ReceiveCandidateList(from, c); err != nil {
			http.Error(w, "reject: "+err.Error(), 400)
			return
		}
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/finalization", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var fin pb.EpochFinalization
		if err := readProtoDelim(r.Body, &fin); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if fin.Signer == nil || len(fin.Signer.V) != 33 {
			http.Error(w, "bad signer", 400)
			return
		}
		if fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 {
			http.Error(w, "bad accepted hash", 400)
			return
		}
		if fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 {
			http.Error(w, "bad frontiers root", 400)
			return
		}
		if fin.Sig == nil || len(fin.Sig.V) < 64 || len(fin.Sig.V) > 80 {
			http.Error(w, "bad sig", 400)
			return
		}

		if err := engine.ReceiveFinalization(&fin); err != nil {
			http.Error(w, "reject: "+err.Error(), 400)
			return
		}
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/tx/inv", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var inv pb.TxInv
		if err := readProtoDelim(r.Body, &inv); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if inv.From == nil || len(inv.From.V) != 33 {
			http.Error(w, "bad from", 400)
			return
		}
		var fromID [33]byte
		copy(fromID[:], inv.From.V)

		// membership against the PER-EPOCH set (manifest list pre-flip / Fund-derived post-flip), the
		// same set /peer/candidates + /peer/finalization use (P7.3 unification; was the static env set,
		// which wrongly refused a newly-admitted banker and accepted a kicked one post-flip).
		if !engine.PeerMemberForEpoch(inv.Epoch, fromID) {
			http.Error(w, "unknown validator", 400)
			return
		}

		want := &pb.TxWant{
			Epoch: inv.Epoch,
			From:  &pb.Pub32{V: inv.From.V},
		}

		for _, h := range inv.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var txid [32]byte
			copy(txid[:], h.V)
			if !engine.HasTx(txid) {
				want.Txid = append(want.Txid, &pb.Hash32{V: h.V})
			}
		}

		log.Printf("[net] rx /peer/tx/inv from=%x epoch=%d inv=%d want=%d", fromID[:4], inv.Epoch, len(inv.Txid), len(want.Txid))
		_ = writeProtoDelim(w, want)
	})

	mux.HandleFunc("/peer/tx/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var push pb.TxPush
		if err := readProtoDelim(r.Body, &push); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if push.From == nil || len(push.From.V) != 33 {
			http.Error(w, "bad from", 400)
			return
		}
		var fromID [33]byte
		copy(fromID[:], push.From.V)
		// Per-epoch membership (P7.3 unification), matching /peer/tx/inv + /peer/candidates.
		if !engine.PeerMemberForEpoch(push.Epoch, fromID) {
			http.Error(w, "unknown validator", 400)
			return
		}

		for _, tx := range push.Tx {
			if tx == nil {
				continue
			}
			raw, err := core.CanonicalTxBytes(tx)
			if err != nil {
				continue
			}
			_ = engine.ReceiveGossipedTx(raw)
		}

		log.Printf("[net] rx /peer/tx/push from=%x epoch=%d txs=%d", fromID[:4], push.Epoch, len(push.Tx))
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/tx/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var want pb.TxWant
		if err := readProtoDelim(r.Body, &want); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		// P7.3: gate /peer/tx/get on the per-epoch set too (it had NO membership check before, so any
		// client could bulk-fetch raw tx bytes). The requester's From is self-asserted — this is a
		// DoS/spam filter, not auth (the IP firewall + consensus sigs are the real boundary) — but it
		// closes the open bulk-read hole and unifies with the other /peer/* handlers.
		if want.From == nil || len(want.From.V) != 33 {
			http.Error(w, "bad from", 400)
			return
		}
		var getFrom [33]byte
		copy(getFrom[:], want.From.V)
		if !engine.PeerMemberForEpoch(want.Epoch, getFrom) {
			http.Error(w, "unknown validator", 400)
			return
		}
		log.Printf("[net] rx /peer/tx/get epoch=%d want=%d", want.Epoch, len(want.Txid))
		out := &pb.TxPush{
			Epoch: want.Epoch,
			From:  &pb.Pub32{V: selfID[:]},
		}

		for _, h := range want.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var txid [32]byte
			copy(txid[:], h.V)
			raw := engine.GetTxBytes(txid)
			if len(raw) == 0 {
				continue
			}
			tx, err := core.ParseTx(raw)
			if err != nil {
				continue
			}
			out.Tx = append(out.Tx, tx)
		}

		log.Printf("[net] ok /peer/tx/get epoch=%d push=%d", out.Epoch, len(out.Tx))
		_ = writeProtoDelim(w, out)
	})

	mux.HandleFunc("/sync/latest", func(w http.ResponseWriter, r *http.Request) {
		latest := engine.LatestFinalizedEpoch()
		_ = writeProtoDelim(w, &pb.SyncLatestResponse{LatestEpoch: latest})
	})

	mux.HandleFunc("/sync/finalization", func(w http.ResponseWriter, r *http.Request) {
		epStr := r.URL.Query().Get("epoch")
		ep, err := strconv.ParseUint(strings.TrimSpace(epStr), 10, 64)
		if err != nil {
			http.Error(w, "need ?epoch=<u64>", 400)
			return
		}
		fins, err := core.GetFinalizations(db, ep)
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			http.Error(w, "db error", 500)
			return
		}
		resp := &pb.SyncFinalizationResponse{}
		for _, raw := range fins {
			var f pb.EpochFinalization
			if err := proto.Unmarshal(raw, &f); err != nil {
				continue
			}
			resp.Finalizations = append(resp.Finalizations, &f)
		}
		_ = writeProtoDelim(w, resp)
	})

	mux.HandleFunc("/sync/frontiers", func(w http.ResponseWriter, r *http.Request) {
		epStr := r.URL.Query().Get("epoch")
		ep, err := strconv.ParseUint(strings.TrimSpace(epStr), 10, 64)
		if err != nil {
			http.Error(w, "need ?epoch=<u64>", 400)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 1000
		}
		if limit > maxFrontiersLimit {
			limit = maxFrontiersLimit // P7.3: ceiling the caller-controlled pagination (resync uses 1000)
		}
		var cursor [32]byte
		if curHex := r.URL.Query().Get("cursor"); curHex != "" {
			b, err := hex.DecodeString(curHex)
			if err == nil && len(b) == 32 {
				copy(cursor[:], b)
			}
		}

		rows, next, err := core.IterEpochFrontiers(db, ep, cursor, limit)
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			http.Error(w, "db error", 500)
			return
		}

		resp := &pb.SyncFrontiersResponse{Epoch: ep}
		for _, row := range rows {
			resp.Entries = append(resp.Entries, &pb.FrontierEntry{
				Account: &pb.AccountId{V: row.AccountID[:]},
				Head:    &pb.Hash32{V: row.HeadHash[:]},
			})
		}
		if next != nil {
			resp.NextCursor = &pb.AccountId{V: next[:]}
		}
		_ = writeProtoDelim(w, resp)
	})

	mux.HandleFunc("/sync/chain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SyncChainRequest
		if err := readProtoDelim(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 || req.TargetHead == nil || len(req.TargetHead.V) != 32 {
			http.Error(w, "bad request", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)
		var head [32]byte
		copy(head[:], req.TargetHead.V)

		var have [32]byte
		if req.Have != nil && len(req.Have.V) == 32 {
			copy(have[:], req.Have.V)
		}

		// P7.3: ceiling the caller-controlled block count (resync asks for 200000, which passes; this
		// only bounds an absurd value). Zero/negative still defaults inside SyncChain.
		maxBlocks := int(req.MaxBlocks)
		if maxBlocks > maxSyncChainBlocks {
			maxBlocks = maxSyncChainBlocks
		}
		txs, reached := engine.SyncChain(acct, head, have, maxBlocks)
		resp := &pb.SyncChainResponse{ReachedHave: reached}
		for _, raw := range txs {
			tx, err := core.ParseTx(raw)
			if err != nil {
				http.Error(w, "bad tx", http.StatusInternalServerError)
				return
			}
			resp.Tx = append(resp.Tx, tx)
		}
		_ = writeProtoDelim(w, resp)
	})

	// ---- Public API endpoints (protobuf) ----

	// POST /submit : SubmitTxRequest -> SubmitTxResponse
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes) // P7.3: bound the io.ReadAll body
		var req pb.SubmitTxRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Tx == nil {
			http.Error(w, "missing tx", 400)
			return
		}
		raw, err := core.CanonicalTxBytes(req.Tx)
		if err != nil {
			http.Error(w, "bad tx", 400)
			return
		}

		// For Logging
		txid, _ := crypto.TxID(req.Tx)

		acct4 := "--------"
		if req.Tx.Account != nil && len(req.Tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", req.Tx.Account.V[:4])
		}

		log.Printf(
			"[api] rx /submit txid=%x acct=%s seq=%d type=%s",
			txid[:4],
			acct4,
			req.Tx.Seq,
			req.Tx.Type.String(),
		)

		resp := &pb.SubmitTxResponse{Ok: false}
		if err := engine.SubmitTx(raw); err != nil {
			resp.Error = &pb.ApiError{Code: 400, Message: "reject", Detail: err.Error()}
			log.Printf("[api] reject /submit txid=%x err=%s", txid[:4], err.Error())
			_ = writeProtoRaw(w, resp)
			return
		}

		resp.Txid = &pb.Hash32{V: txid[:]}
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// POST /account : GetAccountRequest -> GetAccountResponse
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes) // P7.3: bound the io.ReadAll body
		var req pb.GetAccountRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 {
			http.Error(w, "bad account", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)

		rec, err := engine.AccountState(acct)
		resp := &pb.GetAccountResponse{Ok: false}
		if err != nil {
			resp.Error = &pb.ApiError{Code: 500, Message: "error", Detail: err.Error()}
			_ = writeProtoRaw(w, resp)
			return
		}

		state := &pb.AccountState{
			Account:      &pb.AccountId{V: req.Account.V},
			Head:         &pb.Hash32{V: rec.Head[:]},
			Balance:      rec.Balance,
			Seq:          rec.Seq,
			AccountClass: rec.Class,
		}
		// Surface transfer-chain metadata for TRANSFER accounts (zero/absent otherwise).
		if rec.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			state.TransferSource = &pb.AccountId{V: rec.TransferSource[:]}
			state.TransferDestination = &pb.AccountId{V: rec.TransferDest[:]}
			state.TransferUnlockEpoch = rec.TransferUnlock
		}
		resp.State = state
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// POST /receivables : ListReceivablesRequest -> ListReceivablesResponse
	mux.HandleFunc("/receivables", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes) // P7.3: bound the io.ReadAll body
		var req pb.ListReceivablesRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 {
			http.Error(w, "bad account", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)

		recs, err := engine.ListReceivables(acct)
		resp := &pb.ListReceivablesResponse{Ok: false}
		if err != nil {
			resp.Error = &pb.ApiError{Code: 500, Message: "error", Detail: err.Error()}
			_ = writeProtoRaw(w, resp)
			return
		}

		// include_claimed default false
		if !req.IncludeClaimed {
			filtered := make([]*pb.Receivable, 0, len(recs))
			for _, rr := range recs {
				if rr != nil && !rr.Claimed {
					filtered = append(filtered, rr)
				}
			}
			recs = filtered
		}

		resp.Receivables = recs
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// ---- Debug/DB endpoints (JSON) ----

	// GET /debug/accounts/heads
	// Returns all account heads currently stored in bbolt.
	mux.HandleFunc("/debug/accounts/heads", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}

		rows, err := core.ListAllAccountHeads(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}

		type rowJSON struct {
			Account string `json:"account"`
			Head    string `json:"head"`
			Balance uint64 `json:"balance"`
			Seq     uint64 `json:"seq"`
			Class   string `json:"class"`

			// Transfer-chain metadata (populated only for TRANSFER accounts).
			TransferSource    string `json:"transfer_source,omitempty"`
			TransferDest      string `json:"transfer_destination,omitempty"`
			TransferUnlock    uint64 `json:"transfer_unlock_epoch,omitempty"`
			ReleaseNeedsAttsr bool   `json:"release_requires_attestor,omitempty"`
			BreakglassOrigin  bool   `json:"breakglass_origin,omitempty"`   // P5.1: chain opened by a breakglass move
			ReturnDepositTxid string `json:"return_deposit_txid,omitempty"` // P5.5: return-stake chains only

			// Escrow metadata (populated only for ESCROW accounts, P3.3).
			EscrowTrigger  uint64 `json:"escrow_trigger_epoch,omitempty"`
			EscrowAttested bool   `json:"escrow_attested,omitempty"`
		}

		out := make([]rowJSON, 0, len(rows))
		for _, rr := range rows {
			row := rowJSON{
				Account: hex.EncodeToString(rr.Account[:]),
				Head:    hex.EncodeToString(rr.Head[:]),
				Balance: rr.Balance,
				Seq:     rr.Seq,
				Class:   rr.Class.String(),
			}
			if rr.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				row.TransferSource = hex.EncodeToString(rr.TransferSource[:])
				row.TransferDest = hex.EncodeToString(rr.TransferDest[:])
				row.TransferUnlock = rr.TransferUnlock
				row.ReleaseNeedsAttsr = rr.TransferFlags&0x01 != 0
				row.BreakglassOrigin = rr.TransferFlags&0x02 != 0
				if rr.TransferReturnDepositTxid != ([32]byte{}) {
					row.ReturnDepositTxid = hex.EncodeToString(rr.TransferReturnDepositTxid[:])
				}
			}
			if rr.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
				row.EscrowTrigger = rr.EscrowTrigger
				row.EscrowAttested = rr.EscrowFlags&0x01 != 0
			}
			out = append(out, row)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /debug/fund/stakes
	// Dumps the derived stake reference table (P2.2): one row per stake deposit, keyed by
	// deposit_txid. Read-only/additive; the table is a derived cache (not in consensus).
	mux.HandleFunc("/debug/fund/stakes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := core.ListAllStakes(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		type stakeJSON struct {
			DepositTxid string `json:"deposit_txid"`
			StakerID    string `json:"staker_id"`
			StakedFor   string `json:"staked_for"`
			Amount      uint64 `json:"amount"`
			TimeDelay   string `json:"time_delay"`
			Status      uint8  `json:"status"`
		}
		out := make([]stakeJSON, 0, len(rows))
		for _, s := range rows {
			out = append(out, stakeJSON{
				DepositTxid: hex.EncodeToString(s.DepositTxid[:]),
				StakerID:    hex.EncodeToString(s.StakerID[:]),
				StakedFor:   s.StakedFor,
				Amount:      s.Amount,
				TimeDelay:   s.TimeDelay.String(),
				Status:      uint8(s.Status),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /debug/fund/roles
	// Per-identity role derivation over the reference table (P2.2): exercises the Anos-side
	// role predicates (IsBanker/IsAttestor/GuardianWeight) so the live binary surfaces the
	// SAME derivation the later quorum/validator-set chunks consume. One entry per distinct
	// staker identity.
	mux.HandleFunc("/debug/fund/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := core.ListAllStakes(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		type roleJSON struct {
			Identity       string `json:"identity"`
			IsBanker       bool   `json:"is_banker"`
			IsAttestor     bool   `json:"is_attestor"`
			GuardianWeight uint64 `json:"guardian_weight"`
		}
		seen := make(map[[32]byte]struct{})
		out := make([]roleJSON, 0)
		for _, s := range rows {
			if _, ok := seen[s.StakerID]; ok {
				continue
			}
			seen[s.StakerID] = struct{}{}
			out = append(out, roleJSON{
				Identity:       hex.EncodeToString(s.StakerID[:]),
				IsBanker:       econ.IsBanker(rows, s.StakerID),
				IsAttestor:     econ.IsAttestor(rows, s.StakerID),
				GuardianWeight: econ.GuardianWeight(rows, s.StakerID),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /debug/fund/guardians
	// Dumps the derived Guardian-activity projection (P2.3): one row per identity that has
	// contributed a verifying signature to a Fund SEND, with the latest epoch it did so. The
	// active set within the trailing window backs the Fund-SEND quorum denominator. Read-only;
	// the projection is a derived cache (not in consensus) — exposed for cross-node/resync
	// fingerprint comparison.
	mux.HandleFunc("/debug/fund/guardians", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := core.ListGuardianActive(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		type gJSON struct {
			GuardianID      string `json:"guardian_id"`
			LastActiveEpoch uint64 `json:"last_active_epoch"`
		}
		out := make([]gJSON, 0, len(rows))
		for _, g := range rows {
			out = append(out, gJSON{
				GuardianID:      hex.EncodeToString(g.GuardianID[:]),
				LastActiveEpoch: g.LastActiveEpoch,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /debug/fund/bankers
	// Dumps the Fund-DERIVED validator set (P4.1, spec-18 §3.7): every identity that is an active
	// Banker (>= 50k stake) AND carries a valid-key consensus descriptor (consensus P-256 key +
	// endpoint, resolved last-write-wins by deposit send-seq). This is the set the live consensus
	// will read once the P4.3 list→Fund flip latches; in P4.1 it is exposed read-only for cross-node
	// agreement + resync verification (the env list still drives live consensus). Derived cache (not
	// in any consensus hash) — every node computes the identical set from the finalized Fund state.
	mux.HandleFunc("/debug/fund/bankers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		stakes, err := core.ListAllStakes(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		infos, err := core.ListBankerInfo(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		set := econ.BankerValidatorSet(stakes, infos)
		type bJSON struct {
			Identity     string `json:"identity"`
			ConsensusKey string `json:"consensus_pubkey"`
			Endpoint     string `json:"endpoint"`
		}
		out := make([]bJSON, 0, len(set))
		for _, vd := range set {
			out = append(out, bJSON{
				Identity:     hex.EncodeToString(vd.Identity[:]),
				ConsensusKey: hex.EncodeToString(vd.ConsensusKey[:]),
				Endpoint:     vd.Endpoint,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /debug/consensus/flip
	// Surfaces the P4.3 list→Fund activation latch: flip_epoch (0 == still on the manifest list) and
	// whether the live consensus validator-set source has flipped to the Fund-derived set. The
	// manifest list size + the current Fund-derived set size let an operator watch the founders'
	// stakes converge to the list (the flip fires when they match exactly). Read-only; consensus-
	// neutral. (P4.3a; the rigorous chain-verified resync of the flip is P4.3b.)
	mux.HandleFunc("/debug/consensus/flip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		flipEpoch := engine.FlipEpoch()
		stakes, err := core.ListAllStakes(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		infos, err := core.ListBankerInfo(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}
		fundSet := econ.BankerValidatorSet(stakes, infos)
		out := struct {
			FlipEpoch       uint64 `json:"flip_epoch"`
			Flipped         bool   `json:"flipped"`
			Source          string `json:"live_set_source"`
			ManifestSize    int    `json:"manifest_list_size"`
			FundSetSize     int    `json:"fund_set_size"`
			SelfIdentityHex string `json:"self_identity,omitempty"`
		}{
			FlipEpoch:    flipEpoch,
			Flipped:      flipEpoch != 0,
			Source:       map[bool]string{true: "fund", false: "manifest_list"}[flipEpoch != 0],
			ManifestSize: len(validatorSet),
			FundSetSize:  len(fundSet),
		}
		if selfIdentity != ([32]byte{}) {
			out.SelfIdentityHex = hex.EncodeToString(selfIdentity[:])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	// GET /health : ungated liveness probe (no network header, no IP gate, no rate limit) for uptime
	// checks / load balancers. Returns 200 + a tiny JSON with the node's network id + latest epoch.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Status      string `json:"status"`
			NetworkID   string `json:"network_id"`
			LatestEpoch uint64 `json:"latest_epoch"`
		}{"ok", manifest.NetworkID, engine.LatestFinalizedEpoch()})
	})

	// P7.3 edge middlewares, composed OUTSIDE the P7.2 network-id middleware (outer→inner):
	//   debugLoopbackGate → peerIPFirewall → rateLimitGate → anosNetworkMiddleware → mux
	// Each acts only on its own path prefix; the ordering sheds unauthorized / metered traffic as
	// cheaply and early as possible. The http.Server timeouts below are the Slowloris / slow-client
	// defenses (none were set before, so a single slow client could hold a connection open forever).
	submitLimiter := newIPRateLimiter(submitRatePerSec, submitBurst)
	syncLimiter := newIPRateLimiter(syncRatePerSec, syncBurst)
	var handler http.Handler = anosNetworkMiddleware(mux, manifest.NetworkID, manifest.ProtocolVersion)
	handler = rateLimitGate(handler, submitLimiter, syncLimiter, engine.PeerSourceAllowed)
	handler = peerIPFirewall(handler, engine.PeerSourceAllowed)
	handler = debugLoopbackGate(handler)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	log.Printf("validator listening on :%s (peers=%d, epoch=%dms)", port, len(peers), epochMS)

	go func() {
		_ = srv.ListenAndServe()
	}()

	// Shutdown on signal
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	cancel()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(shutdownCtx)

}

// ---------------- Proto helpers ----------------
// Public API: RAW protobuf (no length prefix)
// Peer API:  DELIMITED protobuf (varint length prefix)

func writeProtoRaw(w http.ResponseWriter, msg proto.Message) error {
	w.Header().Set("Content-Type", "application/x-protobuf")
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readProtoRaw(r io.Reader, msg proto.Message) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, msg)
}

func writeProtoDelim(w http.ResponseWriter, msg proto.Message) error {
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

func readProtoDelim(r io.Reader, msg proto.Message) error {
	return protodelim.UnmarshalFrom(bufio.NewReader(r), msg)
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// mustEnv returns a required env var or fatals. Used for the consensus-critical scalars (P7.2):
// with -manifest mandatory the loader always sets these from the validated manifest, so a missing
// value means a broken boot — fail loud rather than fall back to a code-side default that could
// silently fork.
func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required (supplied by the manifest); refusing to boot", k)
	}
	return v
}

// anosNetworkMiddleware enforces the P7.2 network-identity handshake on the consensus wire: every
// /peer/* (except the unauthenticated /peer/id liveness probe) and /sync/* request must carry our
// X-Anos-Network-Id + X-Anos-Protocol-Version, and every such response is stamped with them so the
// resync client can verify the peer it pulled from (bidirectional). It is a misconfiguration guard
// (magic-bytes / chainId), NOT a security boundary — consensus is sig-authed regardless. Public
// /submit, the read API (/account, /receivables), and /debug/* pass through unchanged.
func anosNetworkMiddleware(next http.Handler, networkID string, protocolVersion int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !gatedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set(core.HeaderNetworkID, networkID)
		w.Header().Set(core.HeaderProtocolVersion, strconv.Itoa(protocolVersion))
		if err := core.CheckAnosHeaders(
			r.Header.Get(core.HeaderNetworkID), r.Header.Get(core.HeaderProtocolVersion),
			networkID, protocolVersion); err != nil {
			log.Printf("[peer] rejected %s from %s: %v", r.URL.Path, r.RemoteAddr, err)
			http.Error(w, "network mismatch: "+err.Error(), http.StatusMisdirectedRequest) // 421
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gatedPath reports whether the network-id handshake applies: all /peer/* except the /peer/id
// liveness probe, and all /sync/*.
func gatedPath(p string) bool {
	if p == "/peer/id" {
		return false
	}
	return strings.HasPrefix(p, "/peer/") || strings.HasPrefix(p, "/sync/")
}
