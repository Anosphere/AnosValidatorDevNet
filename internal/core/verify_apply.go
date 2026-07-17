package core

import (
	"bytes"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

var (
	ErrBadSig          = errors.New("bad signature")
	ErrBadPrev         = errors.New("bad prev (must match snapshot head)")
	ErrBadSeq          = errors.New("bad seq")
	ErrInsufficientBal = errors.New("insufficient balance")
	ErrUnknownRecv     = errors.New("unknown receivable_id")
	ErrWrongType       = errors.New("wrong tx type")
	// ErrUnknownStake is returned when a return/kick Fund SEND references a deposit_txid that is
	// not (yet) in the stake reference table. On the live path the stake always exists (the
	// Guardians authorized acting on an existing stake); it can occur transiently during resync
	// if the Fund's chain replays before the staker's deposit chain, so it is a RETRYABLE sentinel
	// in the resync apply loop (like ErrUnknownRecv).
	ErrUnknownStake = errors.New("unknown stake deposit_txid")
)

type Snapshot struct {
	Accounts    map[[32]byte]AccountSnap
	Receivables map[[32]byte]ReceivableSnap
	// Epoch is the current epoch this snapshot is being validated for; used for transfer
	// unlock timing. Set by the engine after buildSnapshot (identical across validators in
	// a given finalization round).
	Epoch uint64
	// DelayEpochs is the TIMELOCKED_DELAY_EPOCHS consensus parameter (must match across
	// validators). Used to enforce the minimum unlock epoch on transfer creation.
	DelayEpochs uint64
	// FundAccount is the reserved manifest-constant Fund id (e.cfg.FundAccount), injected by
	// buildSnapshot. Used to detect a stake deposit (a SEND whose to == Fund id) so the
	// require-routing / valid-tier gates fire identically in validate and apply, AND to detect
	// a Fund SEND (a SEND whose account == Fund id), which is authorized by the weighted
	// Guardian multisig instead of a single Tx.sig. Zero when unset.
	FundAccount [32]byte
	// FundStakeRows is the finalized view of the stake reference table at epoch start, loaded
	// by buildSnapshot. The Fund-SEND quorum (P2.3) reads it to weigh signers (GuardianWeight)
	// and the role derivations consult it. A finalized snapshot keeps the quorum math
	// deterministic across validators in a finalization round.
	FundStakeRows []StakeRow
	// GuardianActiveWeight is the quorum DENOMINATOR M (spec-19 §6.2): the total CURRENT
	// GuardianWeight of identities active within the trailing GUARDIAN_ACTIVE_WINDOW_EPOCHS,
	// precomputed by buildSnapshot from FundStakeRows + BGuardianActive at snap.Epoch. M == 0
	// (genesis / dormant window) collapses the threshold to the N>=1 floor (self-bootstrap).
	GuardianActiveWeight uint64
	// StakeLock1moEpochs / StakeLock1yrEpochs are the per-tier stake lock delays (P2.3b), injected
	// from config. The opening RECEIVE of a Guardian-returned stake's TRANSFER chain enforces
	// unlock >= creation + the staked tier's lock.
	StakeLock1moEpochs uint64
	StakeLock1yrEpochs uint64
	// GuardedDelayEpochs / VaultDelayEpochs are the per-class transfer delays for GUARDED / VAULT
	// sources (P3.2, spec-18 §6), injected from config. delayForSourceClass returns them so a
	// transfer funded by a GUARDED/VAULT account imposes a real lock (VAULT > GUARDED > TIMELOCKED).
	// CONSENSUS-CRITICAL: identical on every validator.
	GuardedDelayEpochs uint64
	VaultDelayEpochs   uint64
	// AttestorQuorumM is the flat M-of-N Fund Attestor quorum threshold (spec-19 §6.1): an
	// attestor-gated TRANSFER release-to-dest needs at least this many DISTINCT verifying Fund
	// Attestor signatures (a count, NOT a weight). CONSENSUS-CRITICAL manifest constant; injected
	// from config. Treated as >= 1 defensively (a zero would make the gate a no-op).
	AttestorQuorumM uint64
	// EscrowAttestationDelayEpochs is the minimum gap (in epochs) between an escrow's creation and
	// its attestation_trigger_epoch (spec-18 §5.6.3, P3.3), injected from config. The escrow opening
	// enforces attestation_trigger_epoch >= creation_epoch + this. CONSENSUS-CRITICAL: identical on
	// every validator.
	EscrowAttestationDelayEpochs uint64
	// BreakglassExtraEpochs is the +1-week fraud-challenge window added to a breakglass move's
	// transfer-chain unlock (spec-18 §6, spec-19 §6.4, P5.1): the chain's unlock floor is
	// creation + delayForSourceClass(sourceClass) + BreakglassExtraEpochs. CONSENSUS-CRITICAL,
	// injected from config (BREAKGLASS_EXTRA_EPOCHS); local test configs set a small value.
	BreakglassExtraEpochs uint64
	// Econ carries the manifest-pinned monetary + role scalars (fee schedule, role floors,
	// Guardian divisor/threshold, fund-send epoch slack) that validation reads (P7.2). buildSnapshot
	// copies e.cfg.Econ into it; the role-derivation methods (IsAttestor / GuardianWeight /
	// GuardianQuorumThreshold) are invoked as snap.Econ.X, and the fee + slack checks read its
	// fields directly. CONSENSUS-CRITICAL: identical on every validator (network_id pins it).
	Econ Economics
	// GenesisSupply is the fixed total supply minted to the genesis account at boot (e.cfg.
	// GenesisSupply), injected by buildSnapshot. The normal-send balance guard rejects any
	// amount above it BEFORE computing amt+fee, closing the uint64-wrap mint (plan §2.7); the
	// supply-total invariant audits against it. Treated as "unset — skip the cap" when 0 so
	// hand-built test snapshots stay valid (buildSnapshot always sets it). CONSENSUS-CRITICAL.
	GenesisSupply uint64
	// GuardedSendMinIntervalEpochs is the guarded/vault outbound rate limit (forquinn
	// confirm-item 2: one new guarded send per 24h, epoch-denominated), injected from config. A
	// SEND from a GUARDED/VAULT account is rejected while snap.Epoch - LastGuardedSendEpoch is
	// below it (first send always allowed). 0 == no limit (pre-wiring test snapshots).
	// CONSENSUS-CRITICAL manifest scalar once wired (phase 2).
	GuardedSendMinIntervalEpochs uint64
}

type AccountSnap struct {
	Head    [32]byte
	Balance uint64
	Seq     uint64
	Class   pb.AccountClass
	// Transfer-chain metadata; only meaningful when Class == ACCOUNT_CLASS_TRANSFER.
	TransferSource [32]byte
	TransferDest   [32]byte
	TransferUnlock uint64
	// TransferFlags carries the TRANSFER_META flags byte; bit 0 = release_requires_attestor
	// (P3.2). The release gate reads it from the finalized snapshot to decide whether a
	// release-to-dest needs the flat M-of-N attestor quorum.
	TransferFlags byte
	// TransferReturnDepositTxid is the original stake row's deposit_txid threaded onto a Fund-sourced
	// RETURN-STAKE chain (P5.5); zero on every ordinary transfer chain. A breakglass-RETURN of the chain
	// to the Fund reads it to mark the BFundStakes row Reverted; validate uses it to require the link.
	TransferReturnDepositTxid [32]byte
	// AuthPubKey is the cached 2625-B hybrid auth pubkey (keys-spec §5.5), used to
	// verify per-tx signatures on an EXISTING account (a SEND or a non-opening
	// RECEIVE). Empty for an account that has not been created yet — an opening
	// RECEIVE carries its own pubkey on the tx instead.
	AuthPubKey []byte
	// BreakglassCommit is the cached 64-B SHA-512 breakglass commitment (keys-spec
	// §7.2). Used when this account is the SOURCE funding a TRANSFER chain: the chain
	// must copy the source's auth pubkey AND breakglass commitment (keys-spec §6.2),
	// so the verifier checks the opening block's carried commitment against this.
	BreakglassCommit []byte

	// U2PubKey is the cached second user key (forquinn item 1): set on a GUARDED/VAULT account
	// at its PoP-verified opening, and on a TRANSFER chain by derived copy from its key source
	// (D2). A single user signature verifies under AuthPubKey (U1) OR U2PubKey; the attestor-free
	// release path (a) requires Tx.sig under U1 AND sig2 under U2. Empty when unregistered.
	U2PubKey []byte
	// LastGuardedSendEpoch is the finalization epoch of the account's most recent SEND —
	// meaningful only for GUARDED/VAULT accounts (the 24h rate limit); 0 == never sent.
	LastGuardedSendEpoch uint64

	// Escrow two-party metadata (ESCROW_META, spec-18 §5.6.2); only meaningful when
	// Class == ACCOUNT_CLASS_ESCROW. The escrow's keyless 2-of-2 outflow verify reads
	// the two parties' stored pubkeys (BY VALUE) off the finalized snapshot — NOT a
	// snap.Accounts[signer_id] lookup. PartyLoPub < PartyHiPub lexicographically.
	EscrowPartyLoPub []byte // 2625 B HybridPubKey, party lo
	EscrowPartyHiPub []byte // 2625 B HybridPubKey, party hi
	// EscrowPartyLoBG / EscrowPartyHiBG are the two parties' 64-B breakglass commitments. Copied into
	// the snapshot in P5.1 so the escrow 2-of-2 verify can accept a slot satisfied by a party's
	// REVEALED breakglass key (spec-19 §6.3, keys-spec §7.3): the revealed key's
	// BreakglassCommitment(·) must equal one of these. Since P5.2 the commitment carries no type byte,
	// so a party's escrow commitment is byte-identical to its normal-account commitment (option-B
	// collapse) — the opener still supplies these and the counterparty verifies its own off-chain.
	EscrowPartyLoBG []byte // 64 B breakglass commitment, party lo
	EscrowPartyHiBG []byte // 64 B breakglass commitment, party hi
	EscrowTrigger   uint64 // attestation_trigger_epoch (1-of-2 → Fund trigger gate, attested only)
	EscrowFlags     byte   // bit 0 = attested-escrow
}

// ReceivableSnap is the epoch-start view of an unclaimed receivable, carrying the fields
// validation needs (notably RequiredDestClass for the source-side routing restriction).
type ReceivableSnap struct {
	From              [32]byte
	To                [32]byte
	Amount            uint64
	RequiredDestClass pb.AccountClass
	// FromSeq is the seq of the SEND that minted this receivable (the source's send
	// seq). It is the creation nonce (creator_seq) when this receivable funds a
	// TRANSFER chain — the chain id = DerivedAccountID(TRANSFER, source pubkey,
	// source id, FromSeq) (keys-spec §6.2).
	FromSeq uint64
	// KeySourceID + ReturnTier are set only for a Guardian-returned stake (P2.3b). KeySourceID is
	// the staker whose keys the opening TRANSFER chain copies (≠ From = the Fund); ReturnTier is
	// the stake's lock tier driving the chain's minimum unlock. Zero/UNSPECIFIED otherwise.
	KeySourceID [32]byte
	ReturnTier  pb.StakeTimeDelay
	// ReturnDelayEpochs is the Guardian-chosen unlock floor (in epochs) for a returned stake's chain
	// (P5.4), stamped from the authorizing Fund SEND. The opening RECEIVE enforces unlock >= creation +
	// this (replacing the P2.3b tier-lock). Meaningful only when KeySourceID is set; 0 otherwise.
	ReturnDelayEpochs uint64
	// FromBreakglass marks a receivable minted by a breakglass move (P5.1): the opening TRANSFER chain
	// gets breakglass_origin + release_requires_attestor and an EXTENDED unlock floor (class delay +
	// BreakglassExtraEpochs). false for every ordinary receivable.
	//
	// (P5.5: the return-stake receivable's return_deposit_txid is NOT snapshotted — ApplyTx reads it
	// straight off the receivable proto to store on the opening chain's TRANSFER_META, and validate has
	// no constraint on it, so no snapshot field is needed.)
	FromBreakglass bool
}

// sigKey* identify WHICH key a tx's single Tx.sig verified under (forquinn D4/D5). The generic
// resolution at the top of ValidateTxAgainstSnapshot accepts U1 OR a registered U2 anywhere a
// single user signature is accepted (D4: hop-1 sends, cancels, non-opening receives, the path-(b)
// user half); the attestor-free release path (a) then requires FIXED roles — Tx.sig under U1 and
// sig2 under U2 (D5) — so the verifier records what actually matched instead of re-deriving it.
const (
	sigKeyNone       = iota // keyless (Fund SEND / escrow outflow — no Tx.sig)
	sigKeyU1                // the account's cached auth pubkey (U1)
	sigKeyU2                // the account's registered second user key (U2)
	sigKeyBreakglass        // the tx's revealed breakglass pubkey
	sigKeyCarried           // an opening RECEIVE's carried auth_pubkey (becomes U1 at apply)
)

// classRequiresU2 reports whether accounts of class c register a second user key U2 at their
// opening (forquinn item 1): GUARDED and VAULT (locked decision 2 extends forquinn's "guarded"
// to both — they are structurally identical but for the delay). Every other class must NOT
// carry a U2 registration; TRANSFER chains get U2 by DERIVED COPY in ApplyTx (D2), never carried.
func classRequiresU2(c pb.AccountClass) bool {
	return c == pb.AccountClass_ACCOUNT_CLASS_GUARDED || c == pb.AccountClass_ACCOUNT_CLASS_VAULT
}

// delayForSourceClass returns the timelock delay (in epochs) that a transfer funded by a
// source of the given class must impose, read from the finalized snapshot's per-class
// constants. TIMELOCKED/GUARDED/VAULT each impose their own delay (VAULT > GUARDED >
// TIMELOCKED by configuration); every other class imposes no delay (0), which the caller
// treats as "this class cannot fund a transfer chain". GUARDED/VAULT additionally set the
// release_requires_attestor flag on the spawned chain (ApplyTx), gating their release.
func delayForSourceClass(c pb.AccountClass, snap *Snapshot) uint64 {
	switch c {
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED:
		return snap.DelayEpochs
	case pb.AccountClass_ACCOUNT_CLASS_GUARDED:
		return snap.GuardedDelayEpochs
	case pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return snap.VaultDelayEpochs
	default:
		return 0
	}
}

// sourceClassRequiresAttestor reports whether a TRANSFER chain funded by a source of class c
// must carry release_requires_attestor (spec-18 §3.3, spec-19 §6.1): GUARDED and VAULT do; a
// Guardian-returned stake's source is the keyless Fund (class FUND) so it does not.
func sourceClassRequiresAttestor(c pb.AccountClass) bool {
	return c == pb.AccountClass_ACCOUNT_CLASS_GUARDED || c == pb.AccountClass_ACCOUNT_CLASS_VAULT
}

// isBaseOwnerClass reports whether c is a sole-owner base account class (SPENDING/TIMELOCKED/
// GUARDED/VAULT) — the classes that hold a single auth key + a breakglass commitment and can
// therefore originate a breakglass drain (P5.1). TRANSFER/ESCROW/FUND are keyless of a single owner
// key (or copy a source's), so they never originate a breakglass drain.
func isBaseOwnerClass(c pb.AccountClass) bool {
	switch c {
	case pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
		pb.AccountClass_ACCOUNT_CLASS_GUARDED,
		pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return true
	}
	return false
}

// stakeLockEpochsForTier maps a stake lock tier to its delay (in epochs) from the snapshot
// config (P2.3b). A Guardian-returned stake's TRANSFER chain must lock at least this long. ok is
// false for an unknown/UNSPECIFIED tier (fail-closed — a return must carry a valid tier).
func stakeLockEpochsForTier(tier pb.StakeTimeDelay, snap *Snapshot) (uint64, bool) {
	switch tier {
	case pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH:
		return snap.StakeLock1moEpochs, true
	case pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR:
		return snap.StakeLock1yrEpochs, true
	default:
		return 0, false
	}
}

// checkBreakglassReveal verifies that a revealed breakglass pubkey is the key committed to by
// storedCommit (keys-spec §7.3, P5.1; class-independent since P5.2). The commitment no longer carries
// an account-type byte, so a transfer/escrow child verifies its COPIED commitment directly with NO
// look-back to the source's class (the P5.2 point). Fails closed: an absent/short commitment — e.g. a
// keyless FUND source, which registers none — or a mismatch both reject. The single-sig signature was
// already verified against the revealed key by the caller; whether the account is ALLOWED a
// breakglass move at all is decided at each call site (base-owner hop-1 drain / breakglass-origin
// TRANSFER hop-2 / breakglass-flagged opening).
func checkBreakglassReveal(revealed, storedCommit []byte) error {
	if len(storedCommit) != breakglassCommitLen {
		return errors.New("breakglass: source account has no registered breakglass commitment")
	}
	if !crypto.VerifyBreakglassReveal(revealed, storedCommit) {
		return errors.New("breakglass: revealed pubkey does not match the stored commitment")
	}
	return nil
}

// requiredDestClassFor returns the destination-class restriction a receivable must carry,
// based on the SENDER's class. TIMELOCKED/GUARDED/VAULT sends may only fund a TRANSFER
// chain; everything else is unrestricted (UNSPECIFIED).
func requiredDestClassFor(senderClass pb.AccountClass) pb.AccountClass {
	switch senderClass {
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
		pb.AccountClass_ACCOUNT_CLASS_GUARDED,
		pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return pb.AccountClass_ACCOUNT_CLASS_TRANSFER
	default:
		return pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED
	}
}

// openingAccountID computes the account-id a creating (opening) RECEIVE must carry,
// and for a TRANSFER chain enforces the copied-key rule (keys-spec §6.2). ap/bg are
// the carried registration fields (already length-checked by the caller). For base
// classes the id is BaseAccountID over the freshly-registered pubkey. For a TRANSFER
// chain the controlling keys are NOT fresh — the chain copies a KEY SOURCE's auth
// pubkey AND breakglass commitment, and its id is derived as
// DerivedAccountID(TRANSFER, keySource pubkey, creatorID, nonce).
//
// For an ordinary transfer the key source IS the creator (the funding source): the
// source's normal key controls the chain (return-to-source = owner cancel) and recovery
// routes back through it. For a Guardian-returned stake (P2.3b) the key source is the
// STAKER (so the staker controls the returned chain) while the creator is the keyless
// FUND (so the id cannot collide with a staker-originated transfer at the same nonce) —
// hence keySource and creator are passed separately. keySrcAuthPub/keySrcBg describe the
// key source and are consulted ONLY for TRANSFER; an unkeyed/missing key source is
// rejected (fail-closed). The id is anchored to the key source's STORED pubkey, and the
// carried ap/bg are separately asserted equal to it, so a forged opening that copies
// neither the keys nor the nonce cannot pass.
func openingAccountID(recvClass pb.AccountClass, ap, bg, keySrcAuthPub, keySrcBg []byte, creatorID [32]byte, nonce uint64) ([32]byte, error) {
	if recvClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		return crypto.BaseAccountID(crypto.AccountTypeByteForClass(recvClass), ap), nil
	}
	if len(keySrcAuthPub) != crypto.HybridPubKeySize || len(keySrcBg) != breakglassCommitLen {
		return [32]byte{}, errors.New("TRANSFER receive: key source not found or not key-registered")
	}
	if !bytes.Equal(ap, keySrcAuthPub) {
		return [32]byte{}, errors.New("TRANSFER chain must copy the key source's auth pubkey")
	}
	if !bytes.Equal(bg, keySrcBg) {
		return [32]byte{}, errors.New("TRANSFER chain must copy the key source's breakglass commitment")
	}
	return crypto.DerivedAccountID(crypto.AccountTypeTransfer, keySrcAuthPub, creatorID, nonce), nil
}

func ParseTx(raw []byte) (*pb.Tx, error) {
	var tx pb.Tx
	if err := proto.Unmarshal(raw, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// ValidateTxAgainstSnapshot verifies signature and semantic validity against epoch-start snapshot.
// Returns computed txid.
func ValidateTxAgainstSnapshot(tx *pb.Tx, snap *Snapshot) ([32]byte, error) {
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return [32]byte{}, errors.New("bad account length")
	}
	var acct [32]byte
	copy(acct[:], tx.Account.V)

	// snapshot view
	as, ok := snap.Accounts[acct]
	if !ok {
		as = AccountSnap{} // zero head/balance/seq
	}

	// Resolve the auth pubkey the hybrid signature must verify against. An
	// account-opening RECEIVE (the account is absent from the snapshot) carries its
	// own pubkey on the tx; every other account tx (SEND, non-opening RECEIVE)
	// verifies against the pubkey cached on the account record. The caller — not
	// crypto — chooses which is authoritative, so a non-opening block cannot
	// substitute a pubkey (enforced in the RECEIVE case below).
	openingAccount := tx.Type == pb.TxType_TX_TYPE_RECEIVE && !ok

	// A Fund SEND (the account being extended IS the Fund) is keyless: it carries no Tx.sig
	// and is authorized SOLELY by the weighted-Guardian HybridMultiSig, verified in the SEND
	// branch below (spec-19 §6.2). Skip the single-signature check for it; every other tx
	// verifies its hybrid signature here against the caller-resolved auth pubkey.
	isFundSend := tx.Type == pb.TxType_TX_TYPE_SEND && snap.FundAccount != ([32]byte{}) && acct == snap.FundAccount
	// An escrow outflow is a SEND extending an EXISTING escrow account: keyless, authorized solely
	// by the 2-of-2 (or 1-of-2 trigger) HybridMultiSig, exactly like a Fund SEND. (An escrow OPENING
	// is a RECEIVE — the account is absent — so it is NOT caught here; it is funder-signed.)
	isEscrowOutflow := tx.Type == pb.TxType_TX_TYPE_SEND && ok && as.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW
	// A breakglass move (P5.1, spec-19 §6.4) is a single-sig tx authorized by the REVEALED breakglass
	// key rather than the cached auth key: the source-drain SEND, the spawned chain's opening RECEIVE,
	// and the hop-2 release SEND. The signature is verified against the revealed key HERE; the
	// commitment match + valid-context checks live in the per-op branches (they need the stored
	// commitment + source class). The revealed key is folded into SignBytesACTE, so it is bound to
	// both the signature and the txid.
	revealedBG := tx.GetRevealedBreakglassPubkey().GetV()
	isBreakglass := len(revealedBG) > 0
	// sig2 — the path-(a) second user signature (forquinn item 1). Like the multisig it is NOT
	// under the signature (a sig can't sign itself; crypto.TxID folds it), so a third party could
	// attach one — it therefore gets the full reject-everywhere-not-expected treatment below:
	// legitimate ONLY on an attestor-flagged TRANSFER release-to-dest (path (a)). Content-based
	// presence, matching the TxID frame (crypto.TxID hard-errors any length outside {0, 4691}).
	sig2 := tx.GetSig2().GetV()
	hasSig2 := len(sig2) > 0
	sigKey := sigKeyNone
	if isFundSend || isEscrowOutflow {
		// A keyless multisig SEND (Fund SEND or escrow outflow) MUST NOT carry a Tx.sig. This is
		// consensus-critical, not cosmetic: crypto.TxID discriminates the multisig-binding txid on
		// Tx.sig == nil, so a keyless SEND that smuggled in a (junk) Tx.sig would be hashed by the
		// single-sig path — whose txid does NOT bind the HybridMultiSig. Two such txs with identical
		// bodies but DIFFERENT signer sets would then share a txid, letting nodes apply divergent
		// multisigs under one txid → a consensus fork. Rejecting Tx.sig here (and at the submit gate)
		// keeps the Tx.sig == nil discriminator sound: every admissible keyless SEND has its multisig
		// bound into its txid.
		if tx.Sig != nil {
			return [32]byte{}, ErrBadSig
		}
		// A keyless multisig SEND must not carry a single-sig breakglass reveal either: the escrow
		// breakglass key rides on a HybridSigEntry, not Tx.revealed_breakglass_pubkey. A reveal here
		// would be folded into SignBytesACTE (changing the digest the multisig signed) for no
		// authorization purpose — reject it so the keyless path stays unambiguous.
		if isBreakglass {
			return [32]byte{}, ErrBadSig
		}
	} else if isBreakglass {
		if len(revealedBG) != crypto.HybridPubKeySize {
			return [32]byte{}, ErrBadSig
		}
		if err := crypto.VerifyTxSignature(tx, revealedBG); err != nil {
			return [32]byte{}, ErrBadSig
		}
		sigKey = sigKeyBreakglass
	} else if openingAccount {
		// An opening is signed by the carried key only (U1 — a U2, if any, is registered ON this
		// block and proves possession via its PoP, never by signing the opening itself).
		if err := crypto.VerifyTxSignature(tx, tx.GetReceive().GetAuthPubkey().GetV()); err != nil {
			return [32]byte{}, ErrBadSig
		}
		sigKey = sigKeyCarried
	} else {
		// Single user signature: U1 OR — when the account registered one — U2 (forquinn D4,
		// uniform at this one resolution site). U2PubKey is set only on GUARDED/VAULT accounts
		// and TRANSFER chains that derived-copied one, so the second try is a no-op elsewhere.
		if err := crypto.VerifyTxSignature(tx, as.AuthPubKey); err == nil {
			sigKey = sigKeyU1
		} else if len(as.U2PubKey) == crypto.HybridPubKeySize && crypto.VerifyTxSignature(tx, as.U2PubKey) == nil {
			sigKey = sigKeyU2
		} else {
			return [32]byte{}, ErrBadSig
		}
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return [32]byte{}, ErrBadSig
	}

	// prev: nil/empty treated as zeros
	var prev [32]byte
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev[:], tx.Prev.V)
	}
	if prev != as.Head {
		return [32]byte{}, ErrBadPrev
	}
	if tx.Seq != as.Seq+1 {
		return [32]byte{}, ErrBadSeq
	}

	// Class validation for normal account-chain transactions.
	if tx.Type == pb.TxType_TX_TYPE_SEND || tx.Type == pb.TxType_TX_TYPE_RECEIVE {
		var txClass pb.AccountClass
		switch tx.Type {
		case pb.TxType_TX_TYPE_SEND:
			sb, _ := tx.Body.(*pb.Tx_Send)
			if sb != nil && sb.Send != nil {
				txClass = sb.Send.AccountClass
			}
		case pb.TxType_TX_TYPE_RECEIVE:
			rb, _ := tx.Body.(*pb.Tx_Receive)
			if rb != nil && rb.Receive != nil {
				txClass = rb.Receive.AccountClass
			}
		}
		if txClass == pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED {
			return [32]byte{}, errors.New("account_class is required for normal account transactions")
		}
		if ok && as.Class != pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED && as.Class != txClass {
			return [32]byte{}, errors.New("account_class mismatch: cannot change class of existing account")
		}
	}

	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb, ok := tx.Body.(*pb.Tx_Send)
		if !ok || sb.Send == nil || sb.Send.To == nil || len(sb.Send.To.V) != 32 {
			return [32]byte{}, ErrWrongType
		}
		amt := sb.Send.Amount
		fee := sb.Send.Fee
		var to [32]byte
		copy(to[:], sb.Send.To.V)

		// Stake-deposit gating (P2.2): a SEND to the Fund carrying a staked_for tag must
		// satisfy the require-routing + valid-tier rules. A TRANSFER-chain drain to the Fund
		// is an allowed stake origin (as.Class == TRANSFER, not restricted); a direct
		// restricted-class stake is rejected here so it never reaches apply.
		if to == snap.FundAccount {
			// D1 (forquinn plan): a restricted-class account may not SEND to the Fund directly AT
			// ALL — a bare donation (empty staked_for) included. A to==Fund send mints no
			// receivable, so the TRANSFER-routing restriction never applies and the send would be
			// a single-sig, windowless, attestor-free, irreversible outbound — exactly the spend
			// shape the guarded/vault protections exist to prevent (coercion/destruction vector).
			// The routed path (drain a TRANSFER chain to the Fund) covers every legitimate need.
			switch as.Class {
			case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
				pb.AccountClass_ACCOUNT_CLASS_GUARDED,
				pb.AccountClass_ACCOUNT_CLASS_VAULT:
				return [32]byte{}, errors.New("restricted-class account cannot send directly to the Fund: route through a transfer chain")
			}
			if err := validateFundStakeSend(as.Class, sb.Send); err != nil {
				return [32]byte{}, err
			}
		}

		// A HybridMultiSig on a SEND is legitimate ONLY for (a) a keyless Fund SEND (the whole
		// authorization) or (b) an attestor-gated TRANSFER release-to-dest (the gate ON TOP of the
		// chain's controlling-key Tx.sig). crypto.TxID folds the multisig into the txid for ANY
		// SEND that carries one, so an attacker could attach length-valid junk entries to grind a
		// low txid; rejecting a multisig wherever it is not expected (here, contextually) keeps a
		// junk-multisig variant of a normal send / return / non-gated release from masquerading as
		// a distinct valid-or-invalid candidate. The submit/gossip gate (bestEffortReleaseCheck)
		// makes the same judgement to keep such a variant out of the conflict pool.
		hasMultiSig := tx.MultiSig != nil && len(tx.MultiSig.Entries) > 0

		// P5.4 stake-recovery fields (recovery_beneficiary / return_delay_epochs / owner_auth) are
		// legitimate ONLY on a Fund SEND (specifically its return / re-attribution sub-modes, gated
		// below). Reject them on every other SEND: they are folded into the txid, so an attacker could
		// otherwise attach length-valid junk to grind a lower txid — the same reasoning that rejects a
		// stray multisig on a normal send.
		if !isFundSend && hasStakeRecoveryFields(sb.Send) {
			return [32]byte{}, errors.New("stake-recovery fields are only valid on a Fund SEND")
		}

		if as.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Outbound from a transfer chain: zero-fee, all-or-nothing drain. Destination is
			// restricted to the stored source (return, any epoch) or the stored destination
			// (release, only at/after unlock).
			if fee != 0 {
				return [32]byte{}, errors.New("transfer outbound must have zero fee")
			}
			if as.Balance == 0 || amt != as.Balance {
				return [32]byte{}, errors.New("transfer outbound must move the full balance (all-or-nothing)")
			}
			// Breakglass control (P5.1 + P5.3, spec-19 §6.4): an outbound may be signed by the REVEALED
			// breakglass key — letting a recoverer who lost the auth key complete the move. The
			// controlling-key signature was verified against the revealed key at the top; here we bind it
			// to the chain's own COPIED commitment (P5.2: the commitment carries no type byte, so no
			// look-back to the source's class is needed) and constrain WHICH destination the reveal may
			// authorize:
			//   - return-to-source (to == TransferSource): P5.3 stuck-child recovery on ORDINARY chains +
			//     P5.5 en-route recovery on Fund-sourced RETURN-STAKE chains. Allowed on ANY chain (not
			//     just a breakglass-origin one). The recovery gate lives at the SOURCE: a revealed key can
			//     only push funds BACK to the safe source (a keyed owner's account, or — for a return-stake
			//     chain — the keyless Fund pool). A thief holding a stolen bg key can only shove value
			//     toward the owner/Fund, never out; at a keyed source the owner's OWN breakglass move then
			//     carries the +1-week window + attestor quorum, and at the Fund the value is simply back in
			//     the pool awaiting a Guardian-authorized C2 recovery (the theft gate). P5.5 lifted the
			//     P5.3 Fund-source rejection; the main switch below enforces the return-deposit link.
			//   - release-to-dest (to == TransferDest): stays breakglass-origin-ONLY. Never release via a
			//     revealed key on an ordinary/return-stake chain (the §3.4 safer path; the source keeps
			//     that power — a return-stake chain is Fund-origin, so a bg release-to-dest is rejected).
			// A `to` that is neither falls through to the destination switch below, which rejects it.
			// A release on a breakglass-origin chain still passes through the attestor-quorum + unlock gate
			// below (release_requires_attestor is set); a return-to-source stays free (ungated) either way.
			if isBreakglass {
				if err := checkBreakglassReveal(revealedBG, as.BreakglassCommit); err != nil {
					return [32]byte{}, err
				}
				switch {
				case to == as.TransferSource:
					// P5.5: a bg return-to-source is now allowed even when the source is the keyless Fund
					// (a return-stake chain). The commitment check above already bound the reveal to the
					// chain's copied staker commitment; the return-deposit-link check + Reverted marking
					// live in the main destination switch / ApplyTx. Nothing Fund-specific to add here.
				case to == as.TransferDest:
					if as.TransferFlags&transferFlagBreakglassOrigin == 0 {
						return [32]byte{}, errors.New("transfer: a revealed breakglass key may release-to-destination only on a breakglass-origin chain")
					}
				}
			}
			switch {
			case to == as.TransferSource:
				// return to source: allowed at any epoch, NEVER attestor-gated (spec-19 §6.1,
				// §7 matrix). The real owner can always cancel — so a multisig here is never
				// expected; reject it (it would only serve to grind the return's txid).
				if hasMultiSig {
					return [32]byte{}, errors.New("transfer return-to-source must not carry a multisig")
				}
				// A cancel is a single-user-sig op (U1 OR U2 via the top resolution): sig2 and the
				// attestor case fields belong only to a release — reject them here (sig2 is
				// third-party-attachable and txid-folded, the same grind class as the multisig).
				if hasSig2 {
					return [32]byte{}, errors.New("transfer return-to-source must not carry a second user signature (sig2)")
				}
				if hasCaseFields(sb.Send) {
					return [32]byte{}, errors.New("transfer return-to-source must not carry attestor case fields")
				}
				// A return-to-source is a CANCEL, never a stake deposit — reject stake-deposit fields
				// (mirrors the P3.3 escrow-outflow guard). Load-bearing for P5.5: a return-stake chain's
				// source IS the keyless Fund, so a return-to-Fund carrying staked_for would append a
				// PHANTOM Fund-attributed stake row via the to==Fund stake-append path (the chain's source
				// resolves to the Fund). An ordinary chain's return-to-source never hits to==Fund, but the
				// reject is correct there too (a cancel is not a stake).
				if sb.Send.GetStakedFor() != "" || sb.Send.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED {
					return [32]byte{}, errors.New("transfer return-to-source must not carry stake-deposit fields")
				}
				// P5.5: a return to the keyless Fund source is the en-route-recovery return of a
				// return-stake chain — ApplyTx marks the referenced BFundStakes row Reverted, so the
				// chain MUST carry the threaded return-deposit link (covers both the bg-signed stuck-key
				// case and an auth-key owner cancel). Every Fund-sourced chain carries one (threaded at
				// creation); fail closed otherwise so a link-less Fund-return never leaves a Returned row
				// stranded while its value silently re-enters the pool.
				if as.TransferSource == snap.FundAccount && as.TransferReturnDepositTxid == ([32]byte{}) {
					return [32]byte{}, errors.New("transfer: Fund-sourced return chain missing its return-deposit link")
				}
			case to == as.TransferDest:
				if snap.Epoch < as.TransferUnlock {
					return [32]byte{}, errors.New("transfer is still locked: release-to-destination not yet allowed")
				}
				// Attestor-gated release (spec-19 §6.1 + forquinn item 1): when
				// release_requires_attestor is set on the chain (a GUARDED/VAULT source — or a
				// breakglass move in P5.1), the release-to-dest is EITHER-OR:
				//   path (a): BOTH user keys — Tx.sig under U1 AND sig2 under U2 — no attestors.
				//   path (b): ONE user key (U1 or U2 via the top resolution; or the revealed
				//             breakglass key on a breakglass-origin chain) + the flat M-of-N Fund
				//             Attestor quorum + the 32-byte case commitment (forquinn item 2).
				// sig2 presence selects the path; the junk combinations (sig2+multisig, sig2 with
				// a U2/breakglass-verified Tx.sig, sig2 on a chain with no U2) all reject, so every
				// {sig, sig2, multisig} shape in the §2.3 txid matrix has exactly one meaning.
				// Otherwise the chain is an ordinary TIMELOCKED release and must NOT carry a
				// multisig, a sig2, or the case fields.
				if as.TransferFlags&transferFlagReleaseRequiresAttestor != 0 {
					if hasSig2 {
						// ---- path (a): U1 + U2, attestor-free (forquinn item 1) ----
						if hasMultiSig {
							return [32]byte{}, errors.New("path (a) release must not carry a multisig (either both user keys or the attestor quorum, never mixed)")
						}
						if hasCaseFields(sb.Send) {
							return [32]byte{}, errors.New("path (a) release must not carry attestor case fields (no attestation backs it)")
						}
						// D5 fixed roles: Tx.sig must have verified under the chain's U1 auth key —
						// a U2- or breakglass-verified Tx.sig plus a sig2 is rejected.
						if sigKey != sigKeyU1 {
							return [32]byte{}, errors.New("path (a) release: Tx.sig must verify under the chain's copied U1 auth key")
						}
						if len(as.U2PubKey) != crypto.HybridPubKeySize {
							return [32]byte{}, errors.New("path (a) release: chain has no registered second user key (U2)")
						}
						if len(sig2) != crypto.HybridSigSize {
							return [32]byte{}, ErrBadSig // unreachable past crypto.TxID's {0,4691} rule; fail closed
						}
						m, _, merr := crypto.MsgHash(tx)
						if merr != nil {
							return [32]byte{}, ErrBadSig
						}
						u2pub, perr := crypto.ParseHybridPubKey(as.U2PubKey)
						if perr != nil {
							return [32]byte{}, errors.New("path (a) release: stored U2 pubkey not parseable")
						}
						s2, serr := crypto.ParseHybridSig(sig2)
						if serr != nil {
							return [32]byte{}, ErrBadSig
						}
						if !crypto.HybridVerify(u2pub, m, s2) {
							return [32]byte{}, errors.New("path (a) release: sig2 does not verify under the chain's U2")
						}
					} else {
						// ---- path (b): one user sig + the attestor quorum ----
						// The case commitment (forquinn item 2): every attestor-gated release —
						// guarded, vault, AND the breakglass hop-2, which flows through this same
						// arm — must carry the 32-byte case_nonce + attestation_hash. Both are
						// folded into the signed preimage, so the user signature and every attestor
						// signature commit to them via m; an attestor signature with no moderation
						// case behind it is invalid by construction. The validator never reads the
						// contents (opaque bytes) — only presence + exact length are enforced. Only
						// {0, 32} lengths ever reach here (SignBytesACTE hard-errors anything else,
						// so a wrong-length field has no computable preimage/txid anywhere).
						if len(sb.Send.GetCaseNonce()) != crypto.CaseFieldSize ||
							len(sb.Send.GetAttestationHash()) != crypto.CaseFieldSize {
							return [32]byte{}, errors.New("attestor-gated release must carry a 32-byte case_nonce and attestation_hash")
						}
						reqM := snap.AttestorQuorumM
						if reqM == 0 {
							reqM = 1 // defensive: a zero-configured M would make the gate a no-op
						}
						if err := verifyReleaseAttestorQuorum(tx, snap, reqM); err != nil {
							return [32]byte{}, err
						}
					}
				} else {
					if hasMultiSig {
						return [32]byte{}, errors.New("transfer release is not attestor-gated: must not carry a multisig")
					}
					if hasSig2 {
						return [32]byte{}, errors.New("transfer release is not attestor-gated: must not carry a second user signature (sig2)")
					}
					if hasCaseFields(sb.Send) {
						return [32]byte{}, errors.New("transfer release is not attestor-gated: must not carry attestor case fields")
					}
				}
			default:
				return [32]byte{}, errors.New("transfer outbound must go to the stored source or destination")
			}
		} else if isFundSend {
			// Fund SEND (spec-18 §7.3, spec-19 §6.2): the only way anos leave the keyless
			// Fund. Zero-fee; partial-balance allowed (unlike a transfer drain). Authorization
			// is the weighted Guardian quorum.
			if hasSig2 {
				return [32]byte{}, errors.New("fund send must not carry a second user signature (sig2)")
			}
			// The case fields belong only to an attestor-gated TRANSFER release (forquinn item 2)
			// — content-based reject, like the sig2/multisig discipline (they are preimage-folded,
			// so a junk-carrying variant would be a distinct meaningless candidate).
			if hasCaseFields(sb.Send) {
				return [32]byte{}, errors.New("fund send must not carry attestor case fields")
			}
			if fee != 0 {
				return [32]byte{}, errors.New("fund send must have zero fee")
			}
			if as.Balance < amt {
				return [32]byte{}, ErrInsufficientBal
			}
			// fund_send_epoch becomes each signer's lastActive on apply (spec-19 §6.2 step 4), so
			// it is bounded on BOTH sides: not in the future (a future claim would inflate the
			// active denominator M), and not stale beyond guardianFundSendEpochSlackEpochs. The
			// lower bound is the security-critical half: without it a Guardian could stamp an
			// ancient epoch on its OWN sends so it never enters the active set M (the denominator)
			// while still counting toward N (eligibility-based) — self-excluding to spend at
			// ~0.7·(others' active weight) instead of ~0.7·(total), every epoch. Bounding
			// staleness forces a frequently-spending signer to stay in M (it can only fall out by
			// being genuinely dormant > a window, which the active-set design intends to exclude).
			fse := sb.Send.GetFundSendEpoch()
			if fse > snap.Epoch {
				return [32]byte{}, fmt.Errorf("fund send: fund_send_epoch %d is in the future (epoch %d)", fse, snap.Epoch)
			}
			if fse+snap.Econ.GuardianFundSendEpochSlackEpochs < snap.Epoch {
				return [32]byte{}, fmt.Errorf("fund send: fund_send_epoch %d is too stale (epoch %d, slack %d)",
					fse, snap.Epoch, snap.Econ.GuardianFundSendEpochSlackEpochs)
			}
			if err := verifyFundSendQuorum(tx, snap); err != nil {
				return [32]byte{}, err
			}
			// Return-stake / kick semantics (P2.3b, spec-19 §6.2). return_deposit_txid selects a
			// stake row the Fund SEND acts on; its presence + the destination distinguish the modes.
			rdt := sb.Send.GetReturnDepositTxid().GetV()
			if len(rdt) == 0 {
				// Plain payout. A Fund SEND to the Fund itself with no stake target is a no-op
				// self-send — disallow it (the only Fund→Fund send acts on a stake: kick / re-attribute).
				if to == snap.FundAccount {
					return [32]byte{}, errors.New("fund send to the Fund must reference a stake to kick")
				}
				// A plain payout acts on no stake row, so it carries no recovery fields.
				if hasStakeRecoveryFields(sb.Send) {
					return [32]byte{}, errors.New("fund payout must not carry stake-recovery fields")
				}
			} else {
				if len(rdt) != 32 {
					return [32]byte{}, errors.New("return_deposit_txid must be 32 bytes")
				}
				// A return/kick must NOT also carry stake-DEPOSIT fields — those belong only to an
				// inbound stake SEND. Rejecting them keeps the input unambiguous and prevents a kick
				// from appending a spurious (Fund-attributed, zero-amount) stake row via the P2.2
				// append path below.
				if sb.Send.GetStakedFor() != "" || sb.Send.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED {
					return [32]byte{}, errors.New("return/kick Fund SEND must not carry stake-deposit fields")
				}
				var dtx [32]byte
				copy(dtx[:], rdt)
				srec, ok := findStakeRow(snap.FundStakeRows, dtx)
				if !ok {
					return [32]byte{}, errors.New("return/kick references an unknown stake")
				}
				// P5.5: a REVERTED row (a returned stake whose Fund-sourced chain was breakglass-RETURNED
				// back to the Fund pool) may be RECOVERED by a C2 generalized return to a beneficiary B — a
				// return (to != Fund) that names recovery_beneficiary. Every other op (kick, re-attribution,
				// normal return-to-staker) still requires an ACTIVE row. The owner-auth theft guard below
				// (a redirect ⇒ the current StakerID's auth/breakglass sig) is unchanged, so a Guardian
				// quorum can ENACT but never REDIRECT the recovered value; ApplyTx flips the row to the
				// TERMINAL Recovered status so it can never be paid out twice.
				recovering := srec.Status == StakeStatusReverted && to != snap.FundAccount &&
					len(sb.Send.GetRecoveryBeneficiary().GetV()) > 0
				if srec.Status != StakeStatusActive && !recovering {
					return [32]byte{}, errors.New("return/kick references a non-recoverable stake")
				}
				if to == snap.FundAccount {
					// Fund → itself moves nothing (amount 0). recovery_beneficiary distinguishes the two
					// modes: unset ⇒ KICK (forfeit); set ⇒ C1 RE-ATTRIBUTION (flip the row's owner A→B in
					// place, keeping it staked).
					if amt != 0 {
						return [32]byte{}, errors.New("kick / re-attribution must move zero amount")
					}
					if bg := sb.Send.GetRecoveryBeneficiary().GetV(); len(bg) > 0 {
						// C1 RE-ATTRIBUTION (P5.4b): re-point row.StakerID A→B, keeping Active/amount/
						// tier/tag. B instantly inherits the stake AND all its per-StakerID role weight
						// (Guardian/Banker/Attestor/voting) with no re-lock, no settlement window. It has
						// no return chain, so it carries no return_delay_epochs. Redirecting ownership
						// requires the current owner's authorization (op = re-attribute).
						if len(bg) != 32 {
							return [32]byte{}, errors.New("recovery_beneficiary must be 32 bytes")
						}
						var b [32]byte
						copy(b[:], bg)
						if b == srec.StakerID {
							return [32]byte{}, errors.New("re-attribution must name a different beneficiary")
						}
						if sb.Send.GetReturnDelayEpochs() != 0 {
							return [32]byte{}, errors.New("re-attribution has no return chain: return_delay_epochs must be 0")
						}
						bAS, ok := snap.Accounts[b]
						if !ok || len(bAS.AuthPubKey) != crypto.HybridPubKeySize || !isBaseOwnerClass(bAS.Class) {
							return [32]byte{}, errors.New("re-attribution beneficiary is not a key-registered base-owner account")
						}
						ownerAS, ok := snap.Accounts[srec.StakerID]
						if !ok {
							return [32]byte{}, errors.New("re-attribution: stake owner is not key-registered")
						}
						if err := verifyStakeOwnerAuth(sb.Send.GetOwnerAuth(), crypto.StakeOwnerAuthOpReattribute, dtx, b, ownerAS); err != nil {
							return [32]byte{}, err
						}
					} else {
						// KICK (forfeit): the stake stays in the pool; carries no recovery fields.
						if hasStakeRecoveryFields(sb.Send) {
							return [32]byte{}, errors.New("kick must not carry stake-recovery fields")
						}
					}
				} else {
					// RETURN-STAKE: the opening TRANSFER chain COPIES a KEY SOURCE's keys and its id is
					// DerivedAccountID(TRANSFER, key-source pubkey, Fund, seq); the amount must equal the
					// staked amount. The key source is the named recovery_beneficiary B for a P5.4 C2
					// GENERALIZED RETURN (withdraw to a new account), else the staker (P2.3b normal
					// return). Redirecting to a non-staker B requires the current owner's authorization.
					if amt != srec.Amount {
						return [32]byte{}, errors.New("return amount must equal the staked amount")
					}
					keySrc := srec.StakerID
					redirect := false
					if bg := sb.Send.GetRecoveryBeneficiary().GetV(); len(bg) > 0 {
						if len(bg) != 32 {
							return [32]byte{}, errors.New("recovery_beneficiary must be 32 bytes")
						}
						copy(keySrc[:], bg)
						redirect = keySrc != srec.StakerID
					}
					ksAS, ok := snap.Accounts[keySrc]
					if !ok || len(ksAS.AuthPubKey) != crypto.HybridPubKeySize || !isBaseOwnerClass(ksAS.Class) {
						return [32]byte{}, errors.New("return: key source is not a key-registered base-owner account")
					}
					wantTo := crypto.DerivedAccountID(crypto.AccountTypeTransfer, ksAS.AuthPubKey, snap.FundAccount, tx.Seq)
					if to != wantTo {
						return [32]byte{}, fmt.Errorf("return: to %x != derived key-source chain id %x", to[:4], wantTo[:4])
					}
					// Unlock floor: a Guardian-chosen return_delay_epochs (P5.4) OVERRIDES the P2.3b
					// forced tier-lock when set (> 0 — "up to them every time"); when unset (0) the
					// floor defaults to the stake's tier-lock. Either way the returned chain must impose
					// a positive lock (P2.3b symmetry), so require a valid basis here — fail closed if
					// neither the override nor the tier yields one.
					if sb.Send.GetReturnDelayEpochs() == 0 {
						if d, ok := stakeLockEpochsForTier(srec.TimeDelay, snap); !ok || d == 0 {
							return [32]byte{}, errors.New("return: no return_delay_epochs override and stake tier has no positive configured lock")
						}
					}
					if redirect {
						// The theft guard: only the CURRENT owner may redirect the stake to a non-staker
						// account. The Guardian quorum (verified above) enacts; owner_auth authorizes the
						// destination. m_owner binds (op=return, deposit_txid, B).
						ownerAS, ok := snap.Accounts[srec.StakerID]
						if !ok {
							return [32]byte{}, errors.New("return: stake owner is not key-registered")
						}
						if err := verifyStakeOwnerAuth(sb.Send.GetOwnerAuth(), crypto.StakeOwnerAuthOpReturn, dtx, keySrc, ownerAS); err != nil {
							return [32]byte{}, err
						}
					} else if hasOwnerAuth(sb.Send) {
						// A return to the staker's own account needs no owner_auth; reject a stray one
						// (it is folded into the txid → grindable). Content-based to match the fold (a
						// present-but-empty owner_auth folds identically to nil → must classify the same).
						return [32]byte{}, errors.New("return to the staker must not carry owner_auth")
					}
				}
			}
		} else if as.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			// Escrow outflow (spec-18 §5.6.1, spec-19 §6.3): keyless, zero-fee, full-balance drain to
			// one recipient, authorized by the 2-of-2 (or the 1-of-2 → Fund attestation trigger) of the
			// two stored parties. The whole authorization is the HybridMultiSig (no Tx.sig — rejected
			// above). The destination is unrestricted (the parties choose where the funds go), so unlike
			// a transfer chain there is no stored source/dest check here.
			if hasSig2 {
				return [32]byte{}, errors.New("escrow outflow must not carry a second user signature (sig2)")
			}
			// The case fields belong only to an attestor-gated TRANSFER release (forquinn item 2):
			// an escrow outflow is party-authorized, never attestor-case-backed.
			if hasCaseFields(sb.Send) {
				return [32]byte{}, errors.New("escrow outflow must not carry attestor case fields")
			}
			if err := verifyEscrowOutflow(tx, sb.Send, as, snap, to, amt, fee); err != nil {
				return [32]byte{}, err
			}
		} else {
			// Normal SEND (or a hop-1 breakglass drain): enforce the fee schedule and balance. A normal
			// send is never multisig-authorized — reject a stray multisig (it would only serve to grind
			// the send's txid, since crypto.TxID folds any SEND multisig into the txid). sig2 is
			// likewise release-only (and equally txid-folded/attachable) — reject it here too.
			if hasMultiSig {
				return [32]byte{}, errors.New("normal send must not carry a multisig")
			}
			if hasSig2 {
				return [32]byte{}, errors.New("normal send must not carry a second user signature (sig2)")
			}
			// The case fields belong only to an attestor-gated TRANSFER release (forquinn item 2):
			// reject them on EVERY normal-arm send — spending/timelocked sends, stake deposits,
			// donations, and the guarded/vault hop-1 (which routes to a transfer chain; the case
			// commitment rides the hop-2 release, never the hop-1). Content-based, matching the
			// preimage fold, same discipline as the multisig/sig2 rejects above.
			if hasCaseFields(sb.Send) {
				if classRequiresU2(as.Class) {
					return [32]byte{}, errors.New("guarded/vault send must not carry attestor case fields")
				}
				return [32]byte{}, errors.New("normal send must not carry attestor case fields")
			}
			// Guarded/vault hop-1 rate limit (forquinn confirm-item 2): one NEW guarded send per
			// rate-limit window. The limit reads the finalized LastGuardedSendEpoch stamped by
			// ApplyTx; first send (stored 0) is always allowed, and interval 0 (pre-wiring test
			// snapshots) is no limit. Subtract form: finalized last <= snap.Epoch always holds.
			if classRequiresU2(as.Class) {
				if last := as.LastGuardedSendEpoch; last != 0 && snap.Epoch-last < snap.GuardedSendMinIntervalEpochs {
					return [32]byte{}, fmt.Errorf("guarded send rate limit: last send finalized at epoch %d, next allowed at %d (now %d)",
						last, last+snap.GuardedSendMinIntervalEpochs, snap.Epoch)
				}
			}
			// Hop-1 breakglass drain (P5.1, spec-19 §6.4): the source account spends via its dormant
			// breakglass key. Bind the revealed key to the source's OWN stored commitment. On apply this
			// mints a FORCED TRANSFER-restricted, breakglass-flagged receivable, so even a SPENDING source
			// routes through a transfer chain + the +1-week window. It must NOT target the keyless Fund (a
			// breakglass move routes through a transfer chain; a TRANSFER-restricted receivable to the Fund
			// could never be claimed). Pays the ordinary first-hop fee (the schedule check below).
			if isBreakglass {
				if err := checkBreakglassReveal(revealedBG, as.BreakglassCommit); err != nil {
					return [32]byte{}, err
				}
				if to == snap.FundAccount {
					return [32]byte{}, errors.New("breakglass move must route through a transfer chain, not target the Fund")
				}
			}
			exp := snap.Econ.RequiredFee(amt)
			if fee != exp {
				return [32]byte{}, errors.New("bad fee")
			}
			// Supply cap + subtract-form balance guard (§2.7): amt is attacker-controlled and
			// unbounded, so the old `Balance < amt+fee` could WRAP (amt=2^64-1 makes amt+fee tiny)
			// and pass for any funded account — minting ~2^64 base units via the receivable. Cap
			// the amount at the total supply (0 == unset skips the cap so hand-built test
			// snapshots stay valid; buildSnapshot always sets it), then prove balance covers
			// amt+fee without ever computing the sum.
			if snap.GenesisSupply != 0 && amt > snap.GenesisSupply {
				return [32]byte{}, errors.New("amount exceeds total supply")
			}
			if as.Balance < amt || as.Balance-amt < fee {
				return [32]byte{}, ErrInsufficientBal
			}
		}

		// If client provided receivable_id, it must match derived value (recipient receivable)
		if sb.Send.ReceivableId != nil && len(sb.Send.ReceivableId.V) == 32 {
			want := crypto.ReceivableIDFromTxID(txid)
			if !bytes.Equal(sb.Send.ReceivableId.V, want[:]) {
				return [32]byte{}, errors.New("receivable_id mismatch")
			}
		}
		return txid, nil

	case pb.TxType_TX_TYPE_RECEIVE:
		rb, ok := tx.Body.(*pb.Tx_Receive)
		if !ok || rb.Receive == nil || rb.Receive.ReceivableId == nil || len(rb.Receive.ReceivableId.V) != 32 {
			return [32]byte{}, ErrWrongType
		}
		var rid [32]byte
		copy(rid[:], rb.Receive.ReceivableId.V)
		rs, ok := snap.Receivables[rid]
		if !ok {
			return [32]byte{}, ErrUnknownRecv // enforces "no same-epoch receive"
		}
		recvClass := rb.Receive.AccountClass

		// sig2 is a SEND-release-only field: never valid on any RECEIVE (it is txid-folded and
		// third-party-attachable, so an unexpected one is the multisig grind class — reject).
		if hasSig2 {
			return [32]byte{}, errors.New("RECEIVE must not carry a second user signature (sig2)")
		}
		// The U2 registration block's ONLY legitimate home is a GUARDED/VAULT account-opening
		// RECEIVE (forquinn item 1; required + verified below). Content-based reject everywhere
		// else — every other opening class (incl. ESCROW, which returns early below, and TRANSFER,
		// which gets U2 by derived copy, D2) and every non-opening RECEIVE.
		if hasU2Registration(rb.Receive) && !(openingAccount && classRequiresU2(recvClass)) {
			return [32]byte{}, errors.New("u2 registration is only valid on a guarded/vault account-opening RECEIVE")
		}

		// First-block key registration enforcement (keys-spec §6.4, §8.3). On the
		// account-opening RECEIVE the auth pubkey + breakglass commitment are required
		// and the account-id MUST equal the hash-derivation from the registered pubkey;
		// a non-opening RECEIVE must not carry them (their only legitimate home is the
		// opening block, where they are folded into the signed preimage).
		if openingAccount {
			// A revealed breakglass key on an OPENING RECEIVE is valid only for a breakglass-spawned
			// TRANSFER chain (the recoverer opens the drain's chain with the breakglass key, having lost
			// the auth key). Reject it on any other opening (FUND/ESCROW/base), where the breakglass key
			// has no role and would only grind the txid.
			if isBreakglass && recvClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				return [32]byte{}, errors.New("revealed breakglass key is only valid on a TRANSFER-chain opening RECEIVE")
			}
			// FUND is a reserved, keyless, manifest-id singleton (keys-spec §6.5, spec-18
			// §7): it is seeded at genesis and NEVER created by a tx. Reject an opening
			// RECEIVE that declares it, so no keyed Class==FUND record can be minted at a
			// vanity (type-byte-0) id. (A SEND may carry account_class==FUND once the Fund
			// itself spends in P2.3; this guard is opening-RECEIVE-only.)
			if recvClass == pb.AccountClass_ACCOUNT_CLASS_FUND {
				return [32]byte{}, errors.New("FUND is a reserved keyless class: cannot be opened by a RECEIVE")
			}
			// An ESCROW opening is keyless-of-a-single-key: it carries BOTH parties' material in
			// escrow_open (not the single-owner auth_pubkey/breakglass_commitment registration), and
			// the funder signs alone. validateEscrowOpening checks the parties, the funder anchor, the
			// id derivation, the trigger delay, and the attested-fee headroom (spec-18 §5.6.3).
			if recvClass == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
				if err := validateEscrowOpening(tx, snap, rs, acct); err != nil {
					return [32]byte{}, err
				}
				return txid, nil
			}
			ap := rb.Receive.GetAuthPubkey().GetV()
			bg := rb.Receive.GetBreakglassCommitment().GetV()
			if len(ap) != crypto.HybridPubKeySize {
				return [32]byte{}, errors.New("opening RECEIVE: auth_pubkey must be present and 2625 bytes")
			}
			if len(bg) != breakglassCommitLen {
				return [32]byte{}, errors.New("opening RECEIVE: breakglass_commitment must be present and 64 bytes")
			}
			// Base classes derive the id from their freshly-registered pubkey; a TRANSFER
			// chain instead copies a KEY SOURCE's auth+breakglass keys and derives the id
			// with the creation nonce (keys-spec §6.2). For an ordinary transfer the key
			// source IS the funding source (rs.From). For a Guardian-returned stake (P2.3b)
			// the key source is the STAKER (rs.KeySourceID) while the creator stays rs.From
			// (the keyless Fund) — so the chain copies the staker's keys but its id cannot
			// collide with a staker-originated transfer. rs.FromSeq is the nonce. Keys come
			// from the snapshot (zero-valued if absent — openingAccountID rejects an
			// unkeyed/missing key source, fail-closed).
			keySrcID := rs.From
			if rs.KeySourceID != ([32]byte{}) {
				keySrcID = rs.KeySourceID
			}
			ks := snap.Accounts[keySrcID]
			wantID, err := openingAccountID(recvClass, ap, bg, ks.AuthPubKey, ks.BreakglassCommit, rs.From, rs.FromSeq)
			if err != nil {
				return [32]byte{}, err
			}
			if wantID != acct {
				return [32]byte{}, fmt.Errorf("opening RECEIVE: account-id %x != derivation %x", acct[:4], wantID[:4])
			}
			// GUARDED/VAULT opening (forquinn item 1/4): the second user key U2 is REQUIRED and
			// its proof-of-possession must verify (m_u2 binds this account id + the pubkey, D12).
			// The block is folded into the U1-signed preimage, so it cannot be stripped/swapped in
			// flight; the PoP forces cryptographic parseability (an unparseable U2 would deadlock
			// path (a) forever) and u2 != auth_pubkey keeps path (a) a real 2-key rule (D6).
			if classRequiresU2(recvClass) {
				if _, err := verifyU2Registration(rb.Receive, acct, ap); err != nil {
					return [32]byte{}, err
				}
			}
			// Breakglass opening (P5.1 + P5.5, spec-19 §6.4): when this RECEIVE is signed by the revealed
			// breakglass key, it opens a stuck chain the recoverer lost the auth key for. It is valid on
			// the TWO openable kinds, and in BOTH the reveal must match the commitment the chain COPIES —
			// the KEY SOURCE's (already resolved as `ks` above), class-independent since P5.2:
			//   - a breakglass-flagged receivable (P5.1): key source == the funding SOURCE (rs.From), so
			//     the reveal matches the source's commitment (rs.FromBreakglass makes the chain
			//     breakglass_origin on apply, regardless of which key opened it).
			//   - a Fund-sourced RETURN-STAKE receivable (P5.5, KeySourceID set): key source == the
			//     staker/beneficiary whose keys the chain copies, while rs.From is the KEYLESS Fund — so
			//     the Fund's (absent) commitment is never consulted. This is the not-yet-opened edge of
			//     en-route recovery (Fund already debited; the staker bg-opens then bg-returns the chain).
			// An auth-key opening (no reveal) of either kind is also allowed — both keys can open it.
			// Reject a reveal on any other TRANSFER opening (it would only grind the txid).
			if recvClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER && isBreakglass {
				if !rs.FromBreakglass && rs.KeySourceID == ([32]byte{}) {
					return [32]byte{}, errors.New("revealed breakglass key may only open a breakglass-flagged or return-stake TRANSFER receivable")
				}
				if err := checkBreakglassReveal(revealedBG, ks.BreakglassCommit); err != nil {
					return [32]byte{}, err
				}
			}
		} else {
			if rb.Receive.GetAuthPubkey() != nil || rb.Receive.GetBreakglassCommitment() != nil {
				return [32]byte{}, errors.New("RECEIVE: auth_pubkey/breakglass_commitment only allowed on the account-opening block")
			}
			// A revealed breakglass key is meaningless on a non-opening RECEIVE (a normal second receive
			// is auth-key signed). Reject it — the top-level verify already (harmlessly) checked the sig
			// against the revealed key, but a non-opening receive must use the cached auth key.
			if isBreakglass {
				return [32]byte{}, errors.New("RECEIVE: revealed breakglass key only allowed on a breakglass TRANSFER-chain opening")
			}
		}

		// Single-funding: a transfer chain and an escrow each accept exactly one RECEIVE (its
		// creation/funding). Escrow single-funding is FIRM by design (spec-18 §5.6.3): one party
		// escrows one amount; top-ups are not planned.
		if as.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER ||
			as.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			return [32]byte{}, errors.New("transfer/escrow chain is single-funding: cannot receive again")
		}

		// Source-side routing restriction: a receivable produced by a class-restricted
		// sender (required_dest_class == TRANSFER) may ONLY be claimed by opening a TRANSFER
		// chain. This is what forces timelocked/guarded/vault funds through a transfer.
		if rs.RequiredDestClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER &&
			recvClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			return [32]byte{}, errors.New("receivable requires a TRANSFER-chain destination")
		}

		// Transfer-chain creation rules.
		if recvClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Must be claiming a transfer-restricted receivable (funded by timelocked/guarded/vault).
			if rs.RequiredDestClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				return [32]byte{}, errors.New("TRANSFER receive must claim a transfer-restricted receivable")
			}
			if rb.Receive.TransferDestination == nil || len(rb.Receive.TransferDestination.V) != 32 {
				return [32]byte{}, errors.New("TRANSFER receive missing transfer_destination")
			}
			// Destination must differ from source: returning to source is always allowed, so a
			// transfer whose destination == source is a degenerate no-op chain. Reject it.
			var dest [32]byte
			copy(dest[:], rb.Receive.TransferDestination.V)
			if dest == rs.From {
				return [32]byte{}, errors.New("TRANSFER destination must differ from source")
			}
			// unlock_epoch must be at least creation_epoch + delay. Using a minimum (>=) rather
			// than exact equality keeps the client robust to which epoch the receive finalizes in,
			// while still guaranteeing at least `delay` epochs of lock. For a Guardian-returned
			// stake the delay is the staked tier's lock (the source is the keyless Fund, which has
			// no class delay); for an ordinary transfer it is the funding source's class delay.
			var delay uint64
			switch {
			case rs.FromBreakglass:
				// Breakglass move (P5.1, spec-19 §6.4, spec-18 §6): the unlock floor is the source class's
				// normal transfer delay PLUS BreakglassExtraEpochs (the +1-week fraud-challenge window in
				// which the real owner can cancel via return-to-source). A SPENDING source has zero class
				// delay, so the window alone applies — and unlike the ordinary branch a zero base delay is
				// NOT rejected. The window itself must be positive (BREAKGLASS_EXTRA_EPOCHS >= 1 is
				// config-enforced) so a breakglass release is never immediate (fail-closed).
				srcClass := snap.Accounts[rs.From].Class
				delay = delayForSourceClass(srcClass, snap) + snap.BreakglassExtraEpochs
				if delay == 0 {
					return [32]byte{}, errors.New("TRANSFER receive: breakglass move has no positive unlock window")
				}
			case rs.KeySourceID != ([32]byte{}):
				// Unlock floor for a returned stake's chain: the Guardian-chosen return_delay_epochs
				// (P5.4) if set, else the stake's tier-lock (P2.3b). Fail closed if neither yields a
				// positive lock, symmetric with the ordinary-transfer delay==0 rejection below.
				if rs.ReturnDelayEpochs > 0 {
					delay = rs.ReturnDelayEpochs
				} else if d, ok := stakeLockEpochsForTier(rs.ReturnTier, snap); ok && d > 0 {
					delay = d
				} else {
					return [32]byte{}, errors.New("TRANSFER receive: return has no positive unlock delay")
				}
			default:
				srcClass := snap.Accounts[rs.From].Class
				delay = delayForSourceClass(srcClass, snap)
				if delay == 0 {
					return [32]byte{}, errors.New("TRANSFER receive: funding account class imposes no transfer delay")
				}
			}
			// Overflow-safe equivalent of: TransferUnlockEpoch < snap.Epoch + delay
			// (avoids a uint64 wrap in the astronomically unlikely event snap.Epoch nears 2^64).
			if rb.Receive.TransferUnlockEpoch < snap.Epoch || rb.Receive.TransferUnlockEpoch-snap.Epoch < delay {
				return [32]byte{}, fmt.Errorf("TRANSFER receive: unlock_epoch %d below minimum (epoch %d + delay %d)",
					rb.Receive.TransferUnlockEpoch, snap.Epoch, delay)
			}
		}
		return txid, nil

	default:
		return [32]byte{}, ErrWrongType
	}
}

// creditFund adds `amount` to the Fund's stored balance (Alt A direct credit,
// spec-18 §7.2) via a read-modify-write of the Fund's account record. It MUST go
// through getAccountRecord/putAccountRecord — never the bare putAccount — so the
// Fund's record shape is preserved (class = FUND, metadata_len 0, and its synthetic
// seed head/seq carried through untouched). The add is a pure, unconditional uint64
// += so it is commutative and therefore order-independent across the many same-epoch
// credits the high-fan-in Fund receives. Fails closed if the Fund record is missing:
// it is seeded at genesis (ensureGenesisOnBoot, idempotent on every boot and after a
// resync wipe), so its absence is an invariant violation, not a routine condition.
func creditFund(tx *bbolt.Tx, fundAcct [32]byte, amount uint64) error {
	rec, ok := getAccountRecord(tx, fundAcct)
	if !ok {
		return fmt.Errorf("fund account %x not seeded", fundAcct[:4])
	}
	rec.Balance += amount
	return putAccountRecord(tx, fundAcct, rec)
}

// validateFundStakeSend gates a stake deposit — a SEND whose destination is the Fund
// carrying a non-empty staked_for tag (build-plan §P2.2, spec-18 §7, spec-19 §5). It is
// called IDENTICALLY from validate (gated on to == snap.FundAccount) and apply (gated on
// toFund), so a tx rejected at validate is never committed and therefore never trips this
// on resync replay. Two consensus-critical rejections:
//
//	(1) Require routing: a restricted-class (TIMELOCKED/GUARDED/VAULT) account may NOT stake
//	    directly — it must route through a TRANSFER chain (drain to the Fund), which copies
//	    the source onto the chain so the stake still attributes to the real owner
//	    (user decision 2026-06-29). A SPENDING account stakes directly; a TRANSFER-chain
//	    drain stakes via its recorded source.
//	(2) Valid tier: a stake must carry a 1-month or 1-year lock tier, since every stake's
//	    Guardian/DAO weight derives from the tier.
//
// It NEVER rejects on the tag value or the amount: staked_for is an open namespace (unknown
// tags stored verbatim) and the Banker/Attestor floors are MEMBERSHIP predicates in the
// reference table, not deposit gates (a sub-floor stake is stored, just not role-eligible).
// A non-stake SEND to the Fund (empty staked_for — e.g. a plain pool contribution or the
// per-send fee credit) is always allowed and records no stake row.
func validateFundStakeSend(senderClass pb.AccountClass, sb *pb.TxBodySend) error {
	if sb.GetStakedFor() == "" {
		return nil
	}
	switch senderClass {
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
		pb.AccountClass_ACCOUNT_CLASS_GUARDED,
		pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return errors.New("stake deposit must route through a transfer chain: a restricted-class account cannot stake directly to the Fund")
	}
	switch sb.GetTimeDelay() {
	case pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH,
		pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR:
		return nil
	default:
		return errors.New("stake deposit requires a valid lock tier (1 month or 1 year)")
	}
}

// verifyFundSendQuorum enforces the weighted-Guardian authorization on a Fund SEND
// (spec-19 §6.2). The Fund is keyless, so the HybridMultiSig is the ENTIRE authorization.
//
//	N (approved)    = Σ GuardianWeight(signer) over DISTINCT entries whose sig AND-verifies
//	                  over m = SHA-256(SignBytesACTE(tx)) against the signer's cached auth
//	                  pubkey AND whose signer is an ELIGIBLE Guardian (GuardianWeight >= 1).
//	                  Eligibility, NOT activeness — passive eligible Guardians still count
//	                  toward N (user decision 2026-06-29, refining spec-19 §6.2 step 1).
//	M (denominator) = snap.GuardianActiveWeight, the ACTIVE Guardian weight from the
//	                  finalized snapshot.
//
// Pass iff N >= ceil(0.70*M) AND N >= 1. M == 0 (genesis / dormant window) collapses the
// threshold to the N>=1 floor, so the first Fund SEND is authorized by any single eligible
// Guardian (self-bootstrapping; no genesis seed). Duplicate signer_ids count once; an entry
// whose signer is unknown/keyless, whose sig fails, or who is not an eligible Guardian is
// IGNORED (not fatal) — only qualifying entries count.
func verifyFundSendQuorum(tx *pb.Tx, snap *Snapshot) error {
	ms := tx.MultiSig
	if ms == nil || len(ms.Entries) == 0 {
		return errors.New("fund send: missing guardian multisig")
	}
	var approved uint64
	if err := eachVerifiedSigner(tx, snap, func(id [32]byte) {
		// A verifying signer that is not an eligible Guardian contributes weight 0 (still
		// deduped by eachVerifiedSigner) — ignored, not fatal.
		approved += snap.Econ.GuardianWeight(snap.FundStakeRows, id)
	}); err != nil {
		return err
	}
	if approved < 1 {
		return errors.New("fund send: needs at least one valid eligible-Guardian signature")
	}
	threshold := snap.Econ.GuardianQuorumThreshold(snap.GuardianActiveWeight)
	if approved < threshold {
		return fmt.Errorf("fund send: approved guardian weight %d < required %d (70%% of active weight %d)",
			approved, threshold, snap.GuardianActiveWeight)
	}
	return nil
}

// hasOwnerAuth reports whether a SEND carries a MEANINGFUL owner_auth — one whose folded CONTENT is
// non-empty (a signature and/or a revealed breakglass pubkey). It MUST match appendStakeRecovery's
// fold exactly (which folds only oa.Sig and oa.RevealedBreakglassPubkey, by value): classifying by
// mere presence (owner_auth != nil) would let a present-but-EMPTY StakeOwnerAuth{} — which folds
// byte-identically to a nil one, yielding the SAME txid — be treated as "carries owner_auth" by the
// validity checks while an absent one is not, so two honest nodes holding the two raws would validate
// the identical txid differently → a fork. Testing folded content keeps the txid discriminator and the
// validity check in lock-step (the same content-vs-presence discipline as the HybridMultiSig, which is
// judged by len(Entries) > 0, not != nil).
func hasOwnerAuth(sb *pb.TxBodySend) bool {
	oa := sb.GetOwnerAuth()
	return len(oa.GetSig().GetV()) > 0 || len(oa.GetRevealedBreakglassPubkey().GetV()) > 0
}

// hasCaseFields reports whether a SEND carries a MEANINGFUL attestor case commitment (forquinn
// item 2): a non-empty case_nonce or attestation_hash. CONTENT-based, matching the SignBytesACTE
// folds (a present-but-empty field folds byte-identically to an absent one — the hasOwnerAuth
// discipline), so the txid discriminator and the validity checks stay in lock-step. Both fields
// are opaque to the validator; SignBytesACTE hard-errors any length outside {0, 32} (D8), so a
// content-present field here is always exactly 32 bytes.
func hasCaseFields(sb *pb.TxBodySend) bool {
	return len(sb.GetCaseNonce()) > 0 || len(sb.GetAttestationHash()) > 0
}

// hasU2Registration reports whether a RECEIVE carries a MEANINGFUL U2 registration block
// (forquinn item 1): a non-empty pubkey or PoP signature. CONTENT-based, matching the
// SignBytesACTE folds, exactly like hasCaseFields/hasOwnerAuth — a present-but-empty
// U2Registration{} folds identically to nil and must classify the same.
func hasU2Registration(rb *pb.TxBodyReceive) bool {
	return len(rb.GetU2().GetPubkey().GetV()) > 0 || len(rb.GetU2().GetPopSig().GetV()) > 0
}

// verifyU2Registration enforces a GUARDED/VAULT opening's second-user-key registration (forquinn
// items 1+4, plan D6/D12): the U2 pubkey and its proof-of-possession signature must be present
// and exact-length, u2 != the carried U1 auth pubkey (else path (a) is single-key theater), and
// the PoP must AND-verify over m_u2 = U2RegistrationDigest(acct, u2_pubkey) — which also forces
// U2's cryptographic parseability (the escrow-opening lesson: a length-valid-but-unparseable key
// would deadlock its verification path forever). Pure function of (tx bytes, acct), so validate,
// ApplyTx (the no-revalidation resync path), and the stateless submit gate (judgeAbsentOpening)
// all call it and agree byte-for-byte. Returns the U2 pubkey bytes for the caller to store.
func verifyU2Registration(rb *pb.TxBodyReceive, acct [32]byte, authPub []byte) ([]byte, error) {
	u2pub := rb.GetU2().GetPubkey().GetV()
	u2pop := rb.GetU2().GetPopSig().GetV()
	if len(u2pub) != crypto.HybridPubKeySize {
		return nil, errors.New("guarded/vault opening: u2 pubkey must be present and 2625 bytes")
	}
	if len(u2pop) != crypto.HybridSigSize {
		return nil, errors.New("guarded/vault opening: u2 proof-of-possession must be present and 4691 bytes")
	}
	if bytes.Equal(u2pub, authPub) {
		return nil, errors.New("guarded/vault opening: u2 pubkey must differ from the auth pubkey")
	}
	m, err := crypto.U2RegistrationDigest(acct, u2pub)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.ParseHybridPubKey(u2pub)
	if err != nil {
		return nil, fmt.Errorf("guarded/vault opening: u2 pubkey not parseable: %w", err)
	}
	sig, err := crypto.ParseHybridSig(u2pop)
	if err != nil {
		return nil, errors.New("guarded/vault opening: malformed u2 proof-of-possession signature")
	}
	if !crypto.HybridVerify(pub, m, sig) {
		return nil, errors.New("guarded/vault opening: u2 proof-of-possession does not verify")
	}
	return u2pub, nil
}

// hasStakeRecoveryFields reports whether a SEND carries any P5.4 in-Fund-stake-recovery field
// (recovery_beneficiary / return_delay_epochs / owner_auth). These are legitimate ONLY on a Fund SEND
// that RETURNS or RE-ATTRIBUTES a stake row; every other SEND rejects them. They are folded into the
// txid (crypto.TxID folds the whole SEND preimage), so an attacker could otherwise attach length-valid
// junk to grind a lower txid — exactly the reason a stray multisig is rejected on a normal send. Each
// clause is CONTENT-based, matching the fold, so a present-but-empty field is byte-identical to (and
// classified the same as) an absent one — no nil-vs-empty txid alias with divergent validity.
func hasStakeRecoveryFields(sb *pb.TxBodySend) bool {
	return len(sb.GetRecoveryBeneficiary().GetV()) > 0 ||
		sb.GetReturnDelayEpochs() != 0 ||
		hasOwnerAuth(sb)
}

// verifyStakeOwnerAuth enforces the stake owner's authorization to REDIRECT a stake to a new
// beneficiary B (P5.4, the theft guard, working notes §3.4). The Guardian quorum authorizes the Fund
// SEND, but only the CURRENT owner's key may name a new destination — so "a quorum can enact but never
// redirect a stake." It verifies oa.sig over m_owner = StakeOwnerAuthDigest(op, deposit_txid, B) against
// the current StakerID's registered auth key, OR — for a recoverer who lost that key — against a
// revealed breakglass key whose BreakglassCommitment(·) equals the staker's stored commitment
// (class-independent since P5.2, exactly like a breakglass move). Fails closed on a missing / malformed
// / non-verifying sig, or an unkeyed owner. Validate-only: ApplyTx never re-verifies it (like Tx.sig and
// the Guardian multisig), so the P4.3b verifying walk replays the recovery byte-identically.
func verifyStakeOwnerAuth(oa *pb.StakeOwnerAuth, op byte, depositTxid, beneficiary [32]byte, owner AccountSnap) error {
	if oa == nil || oa.GetSig() == nil || len(oa.GetSig().GetV()) != crypto.HybridSigSize {
		return errors.New("stake recovery: missing or malformed owner_auth signature")
	}
	sig, err := crypto.ParseHybridSig(oa.GetSig().GetV())
	if err != nil {
		return errors.New("stake recovery: malformed owner_auth signature")
	}
	m := crypto.StakeOwnerAuthDigest(op, depositTxid, beneficiary)
	var pubBytes []byte
	if revealed := oa.GetRevealedBreakglassPubkey().GetV(); len(revealed) > 0 {
		// Owner authorized with the dormant breakglass key (auth key lost): bind it to the staker's
		// OWN stored commitment, exactly like a hop-1 breakglass drain (checkBreakglassReveal).
		if err := checkBreakglassReveal(revealed, owner.BreakglassCommit); err != nil {
			return err
		}
		pubBytes = revealed
	} else {
		if len(owner.AuthPubKey) != crypto.HybridPubKeySize {
			return errors.New("stake recovery: stake owner is not key-registered")
		}
		pubBytes = owner.AuthPubKey
	}
	pub, err := crypto.ParseHybridPubKey(pubBytes)
	if err != nil {
		return errors.New("stake recovery: malformed owner key")
	}
	if !crypto.HybridVerify(pub, m, sig) {
		return errors.New("stake recovery: owner_auth signature does not verify")
	}
	return nil
}

// verifyReleaseAttestorQuorum enforces the flat M-of-N Fund Attestor quorum on an attestor-gated
// TRANSFER release-to-dest (spec-19 §6.1). Unlike the keyless Fund SEND, the release ALSO carries
// the chain's controlling-key Tx.sig (verified separately by VerifyTxSignature) — this is the
// ADDITIONAL gate. It counts DISTINCT entries whose HybridSig AND-verifies over m against the
// signer's cached auth pubkey AND whose signer IsAttestor on the finalized snapshot, requiring the
// count >= reqM (a flat threshold, NOT a weight). Duplicate / unknown / keyless / bad-sig /
// non-Attestor entries are ignored, never fatal — exactly like the Guardian quorum, so a release
// can carry extra non-attestor signatures harmlessly. reqM is the manifest ATTESTOR_QUORUM_M
// (>= 1) for the authoritative epoch-close check, or 1 for the submit-time floor.
func verifyReleaseAttestorQuorum(tx *pb.Tx, snap *Snapshot, reqM uint64) error {
	ms := tx.MultiSig
	if ms == nil || len(ms.Entries) == 0 {
		return errors.New("attestor-gated release: missing attestor multisig")
	}
	var n uint64
	if err := eachVerifiedSigner(tx, snap, func(id [32]byte) {
		if snap.Econ.IsAttestor(snap.FundStakeRows, id) {
			n++
		}
	}); err != nil {
		return err
	}
	if n < reqM {
		return fmt.Errorf("attestor-gated release: %d valid attestor signatures < required %d", n, reqM)
	}
	return nil
}

// eachVerifiedSigner runs the canonical HybridMultiSig verification (spec-19 §4) shared by the
// weighted-Guardian Fund-SEND quorum and the flat-M-of-N attestor release quorum: for each
// DISTINCT well-formed entry whose HybridSig AND-verifies over m = SHA-256(SignBytesACTE(tx))
// against the signer's cached auth pubkey (from the finalized snapshot), it invokes fn(signer_id)
// exactly once. Malformed (wrong-length), duplicate, unknown/keyless, or bad-signature entries are
// skipped (not fatal) — the caller's fn decides the per-signer weight/count and any role gate. It
// returns an error only if the tx digest cannot be computed (a malformed body the caller already
// rejects elsewhere). The dedupe set marks an id the first time it verifies, BEFORE fn runs, so a
// verifying-but-ineligible signer still suppresses a later duplicate entry — preserving the exact
// pre-refactor Fund-SEND semantics.
func eachVerifiedSigner(tx *pb.Tx, snap *Snapshot, fn func(id [32]byte)) error {
	ms := tx.MultiSig
	if ms == nil {
		return nil
	}
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		return err
	}
	counted := make(map[[32]byte]struct{}, len(ms.Entries))
	for _, e := range ms.Entries {
		if e == nil || e.SignerId == nil || len(e.SignerId.V) != 32 ||
			e.Sig == nil || len(e.Sig.V) != crypto.HybridSigSize {
			continue
		}
		var id [32]byte
		copy(id[:], e.SignerId.V)
		if _, dup := counted[id]; dup {
			continue
		}
		as, ok := snap.Accounts[id]
		if !ok || len(as.AuthPubKey) != crypto.HybridPubKeySize {
			continue // unknown or keyless signer — ignored
		}
		pub, perr := crypto.ParseHybridPubKey(as.AuthPubKey)
		if perr != nil {
			continue
		}
		sig, serr := crypto.ParseHybridSig(e.Sig.V)
		if serr != nil {
			continue
		}
		if !crypto.HybridVerify(pub, m, sig) {
			continue // bad signature — ignored
		}
		counted[id] = struct{}{} // a verifying signer counts once (dedupe)
		fn(id)
	}
	return nil
}

// escrowSlotsSigned reports, for an escrow outflow's HybridMultiSig, whether each of the two stored
// party pubkeys has at least one entry whose HybridSig AND-verifies over m (spec-19 §6.3). It
// resolves the party pubkeys BY VALUE from ESCROW_META (loPub/hiPub) — NOT a snap.Accounts[signer_id]
// lookup — so it is a deliberately small escrow-specific verify, not a reuse of eachVerifiedSigner.
// signer_id on the entries is ignored: a slot is satisfied purely by a signature that verifies
// against that party's stored key (the two stored keys are distinct by construction, so one
// signature can satisfy at most one slot). Each slot accepts the party's NORMAL key OR — P5.1,
// spec-19 §6.3, option A — that party's REVEALED breakglass key: an entry carrying a 2625-B
// revealed_breakglass_pubkey whose sig verifies against it AND whose ESCROW-type-byte commitment
// equals that party's stored commitment (loBG/hiBG). Option A binds the revealed key to the stored
// commitment only (the counterparty verifies that commitment off-chain at open, exactly as it
// already verifies its normal pubkey — Anos can't bind it to the party's own account, keys-spec §7.3).
func escrowSlotsSigned(ms *pb.HybridMultiSig, m [32]byte, loPub, loBG, hiPub, hiBG []byte) (lo, hi bool) {
	if ms == nil {
		return false, false
	}
	loP, lerr := crypto.ParseHybridPubKey(loPub)
	hiP, herr := crypto.ParseHybridPubKey(hiPub)
	for _, e := range ms.Entries {
		if lo && hi {
			break
		}
		if e == nil || e.Sig == nil || len(e.Sig.V) != crypto.HybridSigSize {
			continue
		}
		sig, serr := crypto.ParseHybridSig(e.Sig.V)
		if serr != nil {
			continue
		}
		// Normal party key.
		if !lo && lerr == nil && crypto.HybridVerify(loP, m, sig) {
			lo = true
			continue
		}
		if !hi && herr == nil && crypto.HybridVerify(hiP, m, sig) {
			hi = true
			continue
		}
		// Breakglass alternate key: the entry's sig must verify against ITS revealed breakglass pubkey,
		// and that key's commitment must match one of the two stored party commitments. Since P5.2 the
		// commitment carries no type byte, so a party's escrow commitment == its normal-account
		// commitment (escrow option-B collapses); Anos still enforces only that a bg-satisfied slot
		// reveals a key matching that slot's STORED commitment (the counterparty verifies it off-chain
		// at open). The switch fills at most ONE slot per entry (lo preferred), so even a degenerate
		// escrow whose two stored breakglass commitments coincide cannot let a single entry satisfy the
		// whole 2-of-2.
		rbg := e.GetRevealedBreakglassPubkey().GetV()
		if len(rbg) != crypto.HybridPubKeySize {
			continue
		}
		bgP, bgerr := crypto.ParseHybridPubKey(rbg)
		if bgerr != nil || !crypto.HybridVerify(bgP, m, sig) {
			continue
		}
		switch {
		case !lo && crypto.VerifyBreakglassReveal(rbg, loBG):
			lo = true
		case !hi && crypto.VerifyBreakglassReveal(rbg, hiBG):
			hi = true
		}
	}
	return lo, hi
}

// verifyEscrowOutflow enforces escrow governance on a keyless escrow outflow SEND (spec-18 §5.6.1,
// spec-19 §6.3). The escrow holds no single key; the HybridMultiSig is the ENTIRE authorization (no
// Tx.sig). Every escrow outflow is zero-fee and moves the FULL balance (all-or-nothing) to ONE
// recipient (RESOLVED w/ user 2026-06-29). Two authorization modes:
//
//   - 2-of-2 (the default): BOTH stored parties' slots are signed — any destination.
//   - 1-of-2 → Fund attestation trigger (the sole unilateral path, ATTESTED escrows only): ONE slot
//     signed, to == Fund id, at/after attestation_trigger_epoch. A plain escrow has NO trigger, so a
//     single-party outflow (to the Fund or anywhere else) is rejected — a deadlock waits for the 2-of-2.
func verifyEscrowOutflow(tx *pb.Tx, sb *pb.TxBodySend, as AccountSnap, snap *Snapshot, to [32]byte, amt, fee uint64) error {
	if fee != 0 {
		return errors.New("escrow outflow must have zero fee")
	}
	// An escrow outflow must NOT carry stake-deposit fields. Without this, a to==Fund escrow outflow
	// (the 1-of-2 trigger or a 2-of-2 to the Fund) with staked_for set would append a phantom stake
	// row attributed to the keyless escrow id (the Fund stake-append fires on toFund && staked_for),
	// polluting the derived banker/attestor/guardian projections. Mirrors the return/kick strip.
	if sb.GetStakedFor() != "" || sb.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED {
		return errors.New("escrow outflow must not carry stake-deposit fields")
	}
	if as.Balance == 0 || amt != as.Balance {
		return errors.New("escrow outflow must move the full balance (all-or-nothing)")
	}
	ms := tx.MultiSig
	if ms == nil || len(ms.Entries) == 0 {
		return errors.New("escrow outflow: missing multisig")
	}
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		return err
	}
	lo, hi := escrowSlotsSigned(ms, m, as.EscrowPartyLoPub, as.EscrowPartyLoBG, as.EscrowPartyHiPub, as.EscrowPartyHiBG)
	if lo && hi {
		return nil // 2-of-2: any destination
	}
	if lo != hi { // exactly one party slot signed
		attested := as.EscrowFlags&escrowFlagAttested != 0
		toFund := snap.FundAccount != ([32]byte{}) && to == snap.FundAccount
		if attested && toFund && snap.Epoch >= as.EscrowTrigger {
			return nil // 1-of-2 → Fund attestation trigger (attested, at/after the delay)
		}
		return errors.New("escrow outflow: a single party may move the full balance only to the Fund, on an attested escrow, at/after the trigger epoch")
	}
	return errors.New("escrow outflow: needs both parties' signatures (2-of-2)")
}

// validateEscrowOpening enforces the funder-signed escrow opening RECEIVE (spec-18 §5.6.3, keys-spec
// §6.2/§6.4). The funder (the funding source rs.From) signs alone — its Tx.sig is verified at the
// top of ValidateTxAgainstSnapshot against the carried auth_pubkey. This asserts: both parties'
// material is well-formed and in canonical order (party_lo < party_hi, distinct); the funder's
// signing key equals ONE of the two party keys AND equals the funding source's registered key (so
// the signer IS the funder); the escrow id recomputes from EscrowKeyblob(lo,hi) + the funder's
// creation nonce; attestation_trigger_epoch >= creation + ESCROW_ATTESTATION_DELAY_EPOCHS; and the
// funded amount leaves a positive balance after the attested fee (if attested).
func validateEscrowOpening(tx *pb.Tx, snap *Snapshot, rs ReceivableSnap, acct [32]byte) error {
	eo := tx.GetReceive().GetEscrowOpen()
	if eo == nil {
		return errors.New("escrow opening: missing escrow_open")
	}
	// Source-side routing: a TIMELOCKED/GUARDED/VAULT funding source mints a TRANSFER-restricted
	// receivable, which may ONLY be claimed by a TRANSFER chain — so a restricted account cannot fund
	// an escrow directly (only SPENDING can). Enforced here because the escrow opening returns before
	// the generic routing check in ValidateTxAgainstSnapshot's RECEIVE branch.
	if rs.RequiredDestClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		return errors.New("escrow opening: a restricted-class source must route through a transfer chain, not fund an escrow directly")
	}
	loPub := eo.GetPartyLoPubkey().GetV()
	hiPub := eo.GetPartyHiPubkey().GetV()
	loBG := eo.GetPartyLoBreakglassCommit().GetV()
	hiBG := eo.GetPartyHiBreakglassCommit().GetV()
	if len(loPub) != crypto.HybridPubKeySize || len(hiPub) != crypto.HybridPubKeySize {
		return errors.New("escrow opening: each party pubkey must be 2625 bytes")
	}
	if len(loBG) != breakglassCommitLen || len(hiBG) != breakglassCommitLen {
		return errors.New("escrow opening: each party breakglass commitment must be 64 bytes")
	}
	if bytes.Compare(loPub, hiPub) >= 0 {
		return errors.New("escrow opening: parties must be distinct and in canonical order (party_lo < party_hi)")
	}
	// Both party pubkeys must be cryptographically parseable, not merely 2625 bytes — otherwise an
	// escrow could be opened with a length-valid but unparseable counterparty key whose 2-of-2 slot
	// could never be satisfied (escrowSlotsSigned skips a key that fails to parse), deadlocking the
	// escrow. ParseHybridPubKey is pure, so this fails closed identically on every validator.
	if _, err := crypto.ParseHybridPubKey(loPub); err != nil {
		return fmt.Errorf("escrow opening: party_lo pubkey not parseable: %w", err)
	}
	if _, err := crypto.ParseHybridPubKey(hiPub); err != nil {
		return fmt.Errorf("escrow opening: party_hi pubkey not parseable: %w", err)
	}
	// The opening must NOT carry the single-owner breakglass_commitment field (an escrow stores both
	// parties' commitments inside escrow_open; field 6 belongs only to a single-owner opening).
	if tx.GetReceive().GetBreakglassCommitment().GetV() != nil {
		return errors.New("escrow opening: must not carry the single-owner breakglass_commitment")
	}
	// Funder = the signing key (auth_pubkey, already sig-verified at the top). It must be one of the
	// two parties AND the funding source's registered key, anchoring the signer to the actual funder.
	funderPub := tx.GetReceive().GetAuthPubkey().GetV()
	if len(funderPub) != crypto.HybridPubKeySize {
		return errors.New("escrow opening: funder auth_pubkey must be present and 2625 bytes")
	}
	if !bytes.Equal(funderPub, loPub) && !bytes.Equal(funderPub, hiPub) {
		return errors.New("escrow opening: funder must be one of the two parties")
	}
	srcAS, ok := snap.Accounts[rs.From]
	if !ok || !bytes.Equal(funderPub, srcAS.AuthPubKey) {
		return errors.New("escrow opening: funder must be the funding source")
	}
	// Id derivation (keys-spec §6.2): escrow id = DerivedAccountID(ESCROW, keyblob, funder_id, nonce),
	// nonce = the funding SEND's seq (rs.FromSeq), funder_id = rs.From.
	wantID := crypto.DerivedAccountID(crypto.AccountTypeEscrow, crypto.EscrowKeyblob(loPub, hiPub), rs.From, rs.FromSeq)
	if wantID != acct {
		return fmt.Errorf("escrow opening: account-id %x != derivation %x", acct[:4], wantID[:4])
	}
	// attestation_trigger_epoch >= creation + delay (overflow-safe), mirroring the transfer unlock.
	minTrigger := snap.EscrowAttestationDelayEpochs
	if eo.GetAttestationTriggerEpoch() < snap.Epoch || eo.GetAttestationTriggerEpoch()-snap.Epoch < minTrigger {
		return fmt.Errorf("escrow opening: attestation_trigger_epoch %d below minimum (epoch %d + delay %d)",
			eo.GetAttestationTriggerEpoch(), snap.Epoch, minTrigger)
	}
	// The escrow must hold a positive balance after the attested fee, so the full-balance outflow can
	// move something. The funder paid the normal send fee on the funding SEND; the attested fee (if
	// any) is taken out of the deposited amount at the opening apply.
	if eo.GetAttested() {
		if rs.Amount <= snap.Econ.AttestedEscrowFee {
			return fmt.Errorf("escrow opening: attested funding amount %d must exceed the attested fee %d", rs.Amount, snap.Econ.AttestedEscrowFee)
		}
	} else if rs.Amount == 0 {
		return errors.New("escrow opening: funding amount must be positive")
	}
	return nil
}

// recordGuardianActivity refreshes BGuardianActive for a Fund SEND's signers (spec-19 §6.2
// step 4). It records EVERY DISTINCT well-formed signer_id listed in the multisig at the tx's
// fund_send_epoch (keep-the-max), WITHOUT verifying signatures or looking up pubkeys/eligibility.
//
// Why not verify here? Both sig verification and eligibility read OTHER accounts' derived state
// (cached auth pubkeys, stake rows), which is REPLAY-ORDER-DEPENDENT: during resync the signer
// accounts may not be replayed yet when this Fund SEND applies, so a verify-at-apply would record
// a smaller active set than the live path — a divergence in the derived denominator across nodes.
// Recording the listed ids is a PURE function of the tx, so live apply and resync replay produce
// byte-identical projections regardless of order (the resync determinism guarantee). The
// authoritative quorum (verifyFundSendQuorum, which DOES verify against the finalized snapshot)
// already gated the tx at validate.
//
// KNOWN LIMITATION (v1, bounded LOW): because entries are recorded WITHOUT a sig/eligibility check
// here, a party that can land one passing Fund SEND may pad its multisig with EXTRA ids — including
// real-but-dormant Guardians (who keep their full GuardianWeight from the stake table regardless of
// signatures) — marking them "active" and so INFLATING the denominator M for ~one active window.
// That only makes FUTURE Fund SENDs harder (no theft, no lock, self-healing, and the padder must
// already hold a passing quorum), and the per-tx count is bounded by the tx-size cap (P7). A clean
// "record only verifying+eligible signers" rule is NOT available at apply: both checks read
// replay-order-dependent state (auth pubkeys, stake rows), which is exactly what broke live-vs-
// resync determinism. The deferred decline/safety-floor work (spec-19 §6.2) owns active-set
// semantics; v1 accepts the bounded inflation in exchange for replay determinism.
func recordGuardianActivity(tx *bbolt.Tx, parsed *pb.Tx, epoch uint64) error {
	ms := parsed.MultiSig
	if ms == nil {
		return nil
	}
	seen := make(map[[32]byte]struct{}, len(ms.Entries))
	for _, e := range ms.Entries {
		if e == nil || e.SignerId == nil || len(e.SignerId.V) != 32 ||
			e.Sig == nil || len(e.Sig.V) != crypto.HybridSigSize {
			continue
		}
		var id [32]byte
		copy(id[:], e.SignerId.V)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if err := putGuardianActive(tx, id, epoch); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTx applies a validated tx to DB state.
// It assumes prev/seq correctness was checked against snapshot and updates haven't happened mid-commit.
//
// epoch is the FINALIZATION epoch this tx is being committed under — passed by commitEpoch (the live
// loop) and by the resync walk's applyEpochTxids, both of which know it from committed data, so a
// replay is byte-deterministic (plan D3). It is used ONLY to stamp LastGuardedSendEpoch on a
// guarded/vault SEND (the 24h rate limit; stamping lands in phase 2) — no other apply logic may
// become epoch-dependent, and it must NEVER be a wall-clock reading.
func ApplyTx(view *bboltTxView, raw []byte, parsed *pb.Tx, txid [32]byte, fundAcct [32]byte, econ Economics, epoch uint64) error {
	if parsed.Account == nil || len(parsed.Account.V) != 32 {
		return errors.New("bad account")
	}
	var acct [32]byte
	copy(acct[:], parsed.Account.V)

	var head [32]byte
	var bal uint64
	var seq uint64
	var existingClass pb.AccountClass
	var arec AccountRecord // full record (carries transfer metadata for TRANSFER accounts)

	arec, _ = getAccountRecord(view.tx, acct)
	head, bal, seq, existingClass = arec.Head, arec.Balance, arec.Seq, arec.Class

	// If this tx is already the current tip for this chain, treat it as already applied.
	// Do NOT skip merely because the raw tx bytes already exist in BTxs: during resync
	// we can have tx bytes present without the corresponding chain state having advanced.
	if head == txid && seq == parsed.Seq {
		return nil
	}

	// prev compare: nil/empty => zeros
	var prev [32]byte
	if parsed.Prev != nil && len(parsed.Prev.V) == 32 {
		copy(prev[:], parsed.Prev.V)
	}
	if head != prev {
		return fmt.Errorf("%w: have %x want %x", ErrBadPrev, head[:4], prev[:4])
	}
	if parsed.Seq != seq+1 {
		return fmt.Errorf("%w: have %d want %d", ErrBadSeq, seq, parsed.Seq-1)
	}

	switch parsed.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb := parsed.GetSend()
		if sb == nil || sb.To == nil || len(sb.To.V) != 32 {
			return ErrWrongType
		}
		amt := sb.Amount
		fee := sb.Fee
		var toAcct [32]byte
		copy(toAcct[:], sb.To.V)
		toFund := toAcct == fundAcct

		// Shape mirrors of the forquinn validate rules (resync replays committed winners WITHOUT
		// re-validating, so structural requirements derivable from committed data are re-enforced
		// here — a committed tx never trips them, but they fail closed if a malformed one ever
		// reaches apply). sig2 is legitimate ONLY on an attestor-flagged release-to-dest (the
		// either-or gate). The case fields (forquinn item 2) are REQUIRED — exact 32-byte lengths
		// — on the attestor path (the flag-set release WITHOUT a sig2: path (b), incl. the
		// breakglass hop-2) and rejected on every other SEND shape, completing the §2.6 matrix.
		// Structure only: the quorum/signature VERIFICATION stays validate-only (apply trusts the
		// validated winner); everything here derives from committed data, so resync replays it
		// byte-identically.
		hasS2 := len(parsed.GetSig2().GetV()) > 0
		// Mirrors validate's destination switch INCLUDING its order: to == TransferSource matches
		// the return-to-source (cancel) arm FIRST, so a degenerate source==dest record (impossible
		// via a validated opening — "destination must differ from source" — but mirrored anyway
		// for byte-identical replay semantics) classifies as a cancel here exactly as it would in
		// validate, never as an attestor release.
		attestorRelease := existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER &&
			toAcct == arec.TransferDest && toAcct != arec.TransferSource &&
			arec.TransferFlags&transferFlagReleaseRequiresAttestor != 0
		if hasS2 && !attestorRelease {
			return errors.New("sig2 is only valid on an attestor-flagged transfer release-to-dest")
		}
		if attestorRelease && !hasS2 {
			if len(sb.GetCaseNonce()) != crypto.CaseFieldSize || len(sb.GetAttestationHash()) != crypto.CaseFieldSize {
				return errors.New("attestor-gated release must carry a 32-byte case_nonce and attestation_hash")
			}
		} else if hasCaseFields(sb) {
			switch {
			case attestorRelease: // hasS2 set — path (a) never carries the fields
				return errors.New("path (a) release must not carry attestor case fields")
			case existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER && toAcct == arec.TransferSource:
				return errors.New("transfer return-to-source must not carry attestor case fields")
			case classRequiresU2(existingClass):
				return errors.New("guarded/vault send must not carry attestor case fields")
			default:
				return errors.New("send must not carry attestor case fields")
			}
		}

		if existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Outbound from a transfer chain: zero-fee, full-balance drain (all-or-nothing).
			if fee != 0 || bal == 0 || amt != bal {
				return errors.New("transfer outbound must move full balance with zero fee")
			}
			bal = 0
		} else if existingClass == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			// Escrow outflow (spec-18 §5.6.1): zero-fee, full-balance drain (all-or-nothing). The
			// 2-of-2 (or 1-of-2 trigger) quorum was checked at validate; apply trusts the validated
			// winner and does NOT re-run it (resync replays committed winners straight through here).
			// The zero-fee + full-balance guards still fail closed. The destination credit (a recipient
			// receivable, or — for the to==Fund trigger — a direct Fund credit) is handled below.
			if fee != 0 || bal == 0 || amt != bal {
				return errors.New("escrow outflow must move full balance with zero fee")
			}
			// Reject stake-deposit fields (resync-safe mirror of the validate gate): a to==Fund escrow
			// outflow carrying staked_for would otherwise append a phantom stake row to the keyless
			// escrow id via the shared to==Fund stake-append tail below.
			if sb.GetStakedFor() != "" || sb.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED {
				return errors.New("escrow outflow must not carry stake-deposit fields")
			}
			bal = 0
		} else if existingClass == pb.AccountClass_ACCOUNT_CLASS_FUND {
			// Fund SEND (spec-18 §7.3): zero-fee, partial debit. The weighted-Guardian quorum
			// was checked at validate (apply trusts the validated winner and does NOT re-run it
			// — resync replays committed winners straight through here). The zero-fee + balance
			// guards still fail closed. The balance check uses the live (post-credit) balance;
			// since same-epoch credits only INCREASE it above the snapshot value validate
			// approved against, a winner can never under-run here.
			if fee != 0 {
				return errors.New("fund send must have zero fee")
			}
			if bal < amt {
				return ErrInsufficientBal
			}
			bal -= amt
		} else {
			// Enforce fee schedule (SEND only)
			exp := econ.RequiredFee(amt)
			if fee != exp {
				return errors.New("bad fee")
			}
			// Subtract-form mirror of the validate guard (§2.7): never compute amt+fee before
			// proving bal covers it, so a 2^64-boundary amount cannot wrap the check on the
			// no-revalidation resync path either.
			if bal < amt || bal-amt < fee {
				return ErrInsufficientBal
			}
			bal -= amt + fee // no wrap: bal >= amt and bal-amt >= fee ⇒ amt+fee <= bal
		}

		// P5.5: mirror the validate guard — a transfer return-to-source (incl. a return-stake chain back to
		// its keyless Fund source) is a CANCEL, never a stake deposit. Reject stake-deposit fields; without
		// this a return-stake chain returning to the Fund would mint a PHANTOM Fund-attributed stake row via
		// the to==Fund append below (staker resolves to arec.TransferSource == the Fund). Resync-safe: a
		// committed (already-validated) tx never trips it, but it fail-closes should one ever reach apply.
		if existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER && toAcct == arec.TransferSource &&
			(sb.GetStakedFor() != "" || sb.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED) {
			return errors.New("transfer return-to-source must not carry stake-deposit fields")
		}

		// Stake-deposit gate (P2.2), mirrored from ValidateTxAgainstSnapshot so the conditions
		// are byte-identical: a committed (already-validated) tx never trips this, but it
		// fail-closes a malformed stake should one ever reach apply. existingClass is the
		// sender's stored (immutable) class, matching the snapshot class validate used.
		if toFund {
			// D1 mirror: a restricted-class account may not SEND to the Fund directly at all
			// (donation included) — the single-sig windowless outbound the guarded/vault
			// protections exist to prevent. The routed path (TRANSFER-chain drain) is unaffected
			// (its class is TRANSFER).
			switch existingClass {
			case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
				pb.AccountClass_ACCOUNT_CLASS_GUARDED,
				pb.AccountClass_ACCOUNT_CLASS_VAULT:
				return errors.New("restricted-class account cannot send directly to the Fund: route through a transfer chain")
			}
			if err := validateFundStakeSend(existingClass, sb); err != nil {
				return err
			}
		}

		// -------------------------
		// Return-stake / kick (P2.3b)
		// -------------------------
		// A Fund SEND carrying return_deposit_txid acts on a stake row. Look the row up FIRST —
		// before mutating balances/receivables — so on resync, if the Fund's chain replays before
		// the staker's deposit chain, this fails with the RETRYABLE ErrUnknownStake and the whole
		// apply rolls back to be retried once the deposit lands. The status flip is idempotent
		// (keyed by deposit_txid); the deposit's Active write must precede the flip (enforced by
		// that retry), so the final status is order-independent.
		isReturn := false
		var returnStaker [32]byte
		var returnTier pb.StakeTimeDelay
		var returnDelay uint64
		var returnDepositTxid [32]byte // P5.5: threaded onto the return-stake receivable + chain
		reattributed := false
		var reattributeTo [32]byte
		var reattributeTag string
		if existingClass == pb.AccountClass_ACCOUNT_CLASS_FUND {
			rdt := sb.GetReturnDepositTxid().GetV()
			if len(rdt) == 32 {
				// Mirror the validate gate: a return/kick must not carry stake-deposit fields.
				if sb.GetStakedFor() != "" || sb.GetTimeDelay() != pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED {
					return errors.New("return/kick Fund SEND must not carry stake-deposit fields")
				}
				var dtx [32]byte
				copy(dtx[:], rdt)
				srec, ok := getStakeRecord(view.tx, dtx)
				if !ok {
					return ErrUnknownStake
				}
				// P5.5: mirror the validate relaxation — a Reverted row may be C2-recovered (to != Fund,
				// recovery_beneficiary set); every other op requires Active. The transition derives only
				// from the loaded status + signed fields, so resync replays identically (epoch order
				// guarantees the bg-return that set Reverted commits a strictly earlier epoch than this
				// recovery — the recovery's validate could only pass against a snapshot already showing
				// Reverted).
				recovering := srec.Status == StakeStatusReverted && !toFund &&
					len(sb.GetRecoveryBeneficiary().GetV()) > 0
				if srec.Status != StakeStatusActive && !recovering {
					return errors.New("stake already returned/kicked")
				}
				if toFund {
					// Fund → itself (amount 0). recovery_beneficiary distinguishes KICK (unset) from a
					// C1 RE-ATTRIBUTION (set). Effects derive ONLY from the signed/folded fields
					// (recovery_beneficiary + the carried descriptor), never from owner_auth (which
					// ApplyTx never inspects), so resync replays byte-identically.
					if amt != 0 {
						return errors.New("kick / re-attribution must move zero amount")
					}
					if bg := sb.GetRecoveryBeneficiary().GetV(); len(bg) > 0 {
						// C1 RE-ATTRIBUTION (P5.4b): re-point row.StakerID A→B in place, keeping
						// Active/amount/tier/tag. B inherits the stake + all its per-StakerID role weight.
						if len(bg) != 32 {
							return errors.New("recovery_beneficiary must be 32 bytes")
						}
						var b [32]byte
						copy(b[:], bg)
						if b == srec.StakerID {
							return errors.New("re-attribution must name a different beneficiary")
						}
						if sb.GetReturnDelayEpochs() != 0 {
							return errors.New("re-attribution has no return chain: return_delay_epochs must be 0")
						}
						srec.StakerID = b // Status stays Active; Amount/TimeDelay/StakedFor unchanged
						reattributed = true
						reattributeTo = b
						reattributeTag = srec.StakedFor
					} else {
						// KICK (forfeit): the stake stays in the pool; carries no recovery fields.
						if hasStakeRecoveryFields(sb) {
							return errors.New("kick must not carry stake-recovery fields")
						}
						srec.Status = StakeStatusKicked
					}
				} else {
					// RETURN-STAKE: the recipient receivable (minted below) opens a KEY-SOURCE-keyed
					// transfer chain. The key source is the named recovery_beneficiary B (P5.4 C2
					// generalized return) else the staker (P2.3b normal return); capture it + the
					// Guardian-chosen unlock delay to stamp onto the receivable. Effects derive ONLY
					// from the signed/folded fields (recovery_beneficiary, return_delay_epochs), never
					// from owner_auth (which ApplyTx never inspects), so resync replays identically.
					if amt != srec.Amount {
						return errors.New("return amount must equal the staked amount")
					}
					returnStaker = srec.StakerID
					if bg := sb.GetRecoveryBeneficiary().GetV(); len(bg) > 0 {
						if len(bg) != 32 {
							return errors.New("recovery_beneficiary must be 32 bytes")
						}
						copy(returnStaker[:], bg)
					}
					// Guardian-chosen unlock override (P5.4); 0 ⇒ the opening RECEIVE falls back to the
					// stake's tier-lock (the RECEIVE, run in validate, enforces the positive floor).
					returnDelay = sb.GetReturnDelayEpochs()
					// P5.5: a C2 recovery of a Reverted row flips it to the TERMINAL Recovered status (so
					// the recovered value can never be paid out twice); an ordinary return of an Active row
					// flips it to Returned. Derived from the loaded status → resync-deterministic.
					if srec.Status == StakeStatusReverted {
						srec.Status = StakeStatusRecovered
					} else {
						srec.Status = StakeStatusReturned
					}
					isReturn = true
					returnTier = srec.TimeDelay
					returnDepositTxid = dtx // thread the row's deposit_txid onto the receivable + chain (P5.5)
				}
				if err := putStakeRecord(view.tx, dtx, srec); err != nil {
					return err
				}
				// Banker descriptor inheritance (P5.4b): when a BANKER stake is re-attributed A→B, B
				// inherits the validator descriptor CARRIED on this Fund SEND (consensus_pubkey +
				// endpoint) so validator-set membership is seamless (no gap where B IsBanker but is out
				// of the set). It is written at the SENTINEL send-seq 0 — a GLOBAL FLOOR below every real
				// SPENDING banker-deposit seq (>= 2) — so (a) B's own future rotation deposit always
				// overrides it, and (b) seq 0 is comparable with every deposit seq, so keep-max stays
				// order-independent (the P4.1 BBankerInfo determinism invariant) even though this write
				// originates on the Fund chain. The descriptor is CARRIED (folded/Guardian-signed), not
				// read from A's live record, so its value is deterministic (no same-epoch read hazard).
				// recordBankerInfo ignores a malformed/absent key → B registers its own via P4.2 instead.
				if reattributed && reattributeTag == StakedForBanker {
					if err := recordBankerInfo(view.tx, reattributeTo, sb.GetConsensusPubkey(), sb.GetEndpoint(), 0); err != nil {
						return err
					}
				}
			}
		}

		// -------------------------
		// Recipient receivable (amount)
		// -------------------------
		// Alt A (spec-18 §7.2): a SEND whose destination is the Fund mints NO recipient
		// receivable — its amount is credited straight to the Fund balance below (the
		// Fund is keyless and could never claim a receivable). Every other destination
		// keeps the normal user→user receivable.
		rid := crypto.ReceivableIDFromTxID(txid)
		// If client provided receivable_id, it must match (recipient receivable).
		if sb.ReceivableId != nil && len(sb.ReceivableId.V) == 32 && !bytes.Equal(sb.ReceivableId.V, rid[:]) {
			return errors.New("receivable_id mismatch")
		}
		if !toFund {
			rec := &pb.Receivable{
				Id:          &pb.Hash32{V: rid[:]},
				From:        &pb.AccountId{V: acct[:]},
				To:          &pb.AccountId{V: toAcct[:]},
				Amount:      amt,
				Fee:         0, // fee is NOT attached to recipient; the fee is credited to the Fund
				CreatedByTx: &pb.Hash32{V: txid[:]},
				Claimed:     false,
				// Source-side routing restriction, DERIVED from the sender's class: forces a
				// timelocked/guarded/vault holder to claim these funds via a TRANSFER chain.
				RequiredDestClass: requiredDestClassFor(existingClass),
				// The creating SEND's seq — the creation nonce a TRANSFER chain claiming
				// this receivable derives its id from (keys-spec §6.2).
				FromSeq: parsed.Seq,
			}
			if isReturn {
				// A Guardian-returned stake: force a TRANSFER-restricted receivable whose opening
				// chain COPIES THE KEY SOURCE's keys (key_source_id — the staker for a normal return,
				// or the named recovery_beneficiary B for a P5.4 C2 generalized return) and locks at
				// least return_delay_epochs (Guardian-chosen, P5.4). From is the keyless Fund (the
				// chain's creator + return target); the chain id derives from the key source's pubkey +
				// creator=Fund + this seq. return_tier is stamped for the record (the stake's original
				// tier) but the unlock floor now comes from return_delay_epochs.
				rec.RequiredDestClass = pb.AccountClass_ACCOUNT_CLASS_TRANSFER
				rec.KeySourceId = &pb.AccountId{V: append([]byte(nil), returnStaker[:]...)}
				rec.ReturnTier = returnTier
				rec.ReturnDelayEpochs = returnDelay
				// P5.5: thread the ORIGINAL stake row's deposit_txid onto the receivable (echoed from the
				// authorizing Fund SEND's signed return_deposit_txid), so the opening RECEIVE can store it
				// immutably on the chain's TRANSFER_META. A later breakglass-RETURN of the chain to the Fund
				// reads it to mark the row Reverted. Derived (not signed here) — the link rides the txid via
				// the Fund SEND's already-folded return_deposit_txid, so no new fold is needed.
				rec.ReturnDepositTxid = &pb.Hash32{V: append([]byte(nil), returnDepositTxid[:]...)}
			}
			// Breakglass drain (P5.1, spec-19 §6.4): a SEND from a base-owner account carrying a
			// revealed breakglass key FORCES TRANSFER routing (even an unrestricted SPENDING source) and
			// marks the receivable so its opening TRANSFER chain becomes breakglass_origin + gets the
			// extended unlock. Derived purely from the (signed, txid-bound) presence of the reveal +
			// the sender's stored class, so resync replay reproduces it without re-verifying the sig.
			// validate already bound the reveal to the source's commitment + forbade to==Fund.
			if len(parsed.GetRevealedBreakglassPubkey().GetV()) > 0 && isBaseOwnerClass(existingClass) {
				rec.RequiredDestClass = pb.AccountClass_ACCOUNT_CLASS_TRANSFER
				rec.FromBreakglass = true
			}
			rr, _ := proto.Marshal(rec)
			if err := putReceivableRaw(view.tx, rid, rr); err != nil {
				return err
			}
		}

		seq = parsed.Seq
		head = txid
		// Write the sender's account back, preserving any transfer metadata (read-modify-write).
		arec.Head = head
		arec.Balance = bal
		arec.Seq = seq
		arec.Class = existingClass
		// Guarded/vault rate-limit stamp (§2.8): record the FINALIZATION epoch of this SEND —
		// the epoch parameter is committed data (commitEpoch / the resync walk both know it), so
		// replay stamps the identical value. The interval check itself runs in validate against
		// the finalized snapshot (like the transfer-unlock window); apply's job is the stamp.
		if classRequiresU2(existingClass) {
			arec.LastGuardedSendEpoch = epoch
		}
		if err := putAccountRecord(view.tx, acct, arec); err != nil {
			return err
		}

		// -------------------------
		// Alt A direct Fund credit (spec-18 §7.2)
		// -------------------------
		// Replaces the old per-send fee receivable. Two destination-driven credits, both
		// applied as a deterministic side-effect of this SEND: the fee on every fee-bearing
		// normal send, and the amount of any send whose to == Fund id. The credit MUST be a
		// pure, unconditional uint64 += (creditFund branches on nothing about the running
		// balance) so it is order-independent across the many same-epoch credits the
		// high-fan-in Fund receives. The early idempotency return above (head == txid && seq
		// matches) keeps a re-apply from double-crediting, so resync replay reproduces the
		// identical balance. Credited AFTER the sender write so a future Fund-as-sender path
		// (P2.3) would read its post-debit record. (Transfer outbound is zero-fee, so fee==0
		// there; a transfer draining TO the Fund still credits its full amount.)
		fundCredit := fee
		if toFund {
			fundCredit += amt
		}
		if fundCredit > 0 {
			if err := creditFund(view.tx, fundAcct, fundCredit); err != nil {
				return err
			}
		}

		// -------------------------
		// En-route stake recovery: mark the row Reverted (P5.5, spec-18 §7.5, working notes §3.4 (D))
		// -------------------------
		// When a Fund-sourced RETURN-STAKE chain is RETURNED to its Fund source (its value was credited
		// back to the pool just above), mark the referenced BFundStakes row Reverted — the auditable,
		// Guardian-actionable trail that the stake is home and awaiting a C2 recovery to a new owner B.
		// Derived PURELY from committed state (the chain's immutable TransferSource + the threaded
		// return_deposit_txid) + the destination (to == Fund), never from the reveal — so it fires
		// identically for the bg-signed stuck-key return and an auth-key owner cancel, and a resync
		// replays it byte-identically. The chain drains exactly once (all-or-nothing), so this fires once;
		// the Returned→Reverted guard makes it idempotent and never clobbers a terminal status.
		if existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER && toFund &&
			arec.TransferSource == fundAcct && arec.TransferReturnDepositTxid != ([32]byte{}) {
			srec, ok := getStakeRecord(view.tx, arec.TransferReturnDepositTxid)
			if !ok {
				// The row is a causal ANCESTOR of this chain (staker deposit → Fund return SEND that set it
				// Returned → this chain's opening RECEIVE → this drain), so it is always present here. Treat
				// an absence as a retryable resync-ordering hiccup (rolls back + retries, like the P2.3b
				// return path) rather than a silent skip — a silent skip could diverge from a live run that
				// saw the row.
				return ErrUnknownStake
			}
			if srec.Status == StakeStatusReturned {
				srec.Status = StakeStatusReverted
				if err := putStakeRecord(view.tx, arec.TransferReturnDepositTxid, srec); err != nil {
					return err
				}
			}
		}

		// -------------------------
		// Stake reference-table append (P2.2, spec-18 §7 / spec-19 §5)
		// -------------------------
		// A to==Fund SEND carrying a non-empty staked_for tag is a stake deposit: record it
		// in the derived reference table, keyed by this SEND's txid (deposit_txid). Staker
		// attribution follows the funding chain — a TRANSFER chain draining to the Fund
		// attributes the stake to its stored source (the original owner), so a restricted
		// account that routed through a transfer chain is credited under its own identity;
		// any other (SPENDING) sender is itself the staker. Like creditFund this is a derived
		// side-effect (NOT in any consensus hash) reproduced on every replay path; keying by
		// deposit_txid makes the write idempotent, so resync rebuilds the table identically.
		// Sits after the idempotency guard above (head==txid && seq) so a re-apply is a no-op.
		if toFund && sb.GetStakedFor() != "" && len(sb.GetReturnDepositTxid().GetV()) == 0 {
			staker := acct
			if existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				staker = arec.TransferSource
			}
			if err := putStakeRecord(view.tx, txid, StakeRecord{
				StakerID:  staker,
				Amount:    amt,
				TimeDelay: sb.GetTimeDelay(),
				Status:    StakeStatusActive,
				StakedFor: sb.GetStakedFor(),
			}); err != nil {
				return err
			}
			// Banker validator-descriptor projection (P4.1, spec-18 §3.7): a "banker"-tagged deposit
			// carries the validator's consensus key + endpoint. Record them under the staking identity,
			// last-write-wins by this deposit's send-seq (recordBankerInfo keeps the max and ignores a
			// malformed key — membership-not-rejection). Derived side-effect (BBankerInfo, not in any
			// consensus hash), reproduced deterministically on replay — the send-seq is on the signed tx.
			//
			// ONLY a DIRECT SPENDING banker deposit registers a descriptor (a validator is a live
			// SPENDING account). A restricted-class identity's "banker" stake routed through a transfer
			// chain (existingClass == TRANSFER) still records the STAKE for weight/voting, but contributes
			// NO descriptor. This is consensus-critical for the projection's DETERMINISM: a transfer-chain
			// drain is always seq 2 (every chain's blocks restart at seq 1), so two routed banker deposits
			// attributed to one identity would COLLIDE on send-seq → keep-max's equal-seq tie is
			// replay-order-dependent → cross-node / resync divergence in BBankerInfo. A SPENDING account is
			// provably never a TransferSource (a transfer chain is funded only by a restricted-class
			// sender's TRANSFER-restricted receivable), so a SPENDING identity's banker deposits all share
			// its single monotonic chain → the send-seqs strictly increase → keep-max is well-defined.
			if sb.GetStakedFor() == StakedForBanker && existingClass == pb.AccountClass_ACCOUNT_CLASS_SPENDING {
				if err := recordBankerInfo(view.tx, acct, sb.GetConsensusPubkey(), sb.GetEndpoint(), parsed.Seq); err != nil {
					return err
				}
			}
		}

		// -------------------------
		// Guardian-activity projection (P2.3, spec-19 §6.2)
		// -------------------------
		// A Fund SEND refreshes lastActive for each of its verifying signers — the trailing-
		// window active set is the quorum denominator for FUTURE Fund SENDs. Derived side-effect
		// (BGuardianActive, not in any consensus hash), reproduced on replay; the activation
		// epoch comes from the signed tx (fund_send_epoch) so it is replay-deterministic. Runs
		// after the idempotency guard above so a re-apply is a no-op (and putGuardianActive keeps
		// the max regardless).
		if existingClass == pb.AccountClass_ACCOUNT_CLASS_FUND {
			if err := recordGuardianActivity(view.tx, parsed, sb.GetFundSendEpoch()); err != nil {
				return err
			}
		}
		return putTxRaw(view.tx, txid, raw)

	case pb.TxType_TX_TYPE_RECEIVE:
		rb := parsed.GetReceive()
		if rb == nil || rb.ReceivableId == nil || len(rb.ReceivableId.V) != 32 {
			return ErrWrongType
		}
		// Shape mirror (resync replays without validate): sig2 is a SEND-release-only field,
		// never valid on any RECEIVE.
		if len(parsed.GetSig2().GetV()) > 0 {
			return errors.New("RECEIVE must not carry a second user signature (sig2)")
		}
		var rid [32]byte
		copy(rid[:], rb.ReceivableId.V)

		rr, err := getReceivableRaw(view.tx, rid)
		if err != nil {
			return ErrUnknownRecv
		}
		var rec pb.Receivable
		if err := proto.Unmarshal(rr, &rec); err != nil {
			return err
		}
		if rec.Claimed {
			return errors.New("receivable already claimed")
		}
		if rec.To == nil || rec.To.V == nil || !bytesEq32(rec.To.V, acct) {
			return errors.New("receivable not for this account")
		}

		// mark claimed and credit
		bal += rec.Amount
		rec.Claimed = true
		rec.ClaimedByTx = &pb.Hash32{V: txid[:]}

		nrr, _ := proto.Marshal(&rec)
		if err := putReceivableRaw(view.tx, rid, nrr); err != nil {
			return err
		}

		// Determine class to persist.
		// If the account already has a class, keep it (validation already confirmed tx class matches).
		// If this is a new account (existingClass is UNSPECIFIED), establish class from this tx.
		classToStore := existingClass
		creating := existingClass == pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED
		if creating {
			classToStore = rb.AccountClass
			// Mirror the validate-path guard (keys-spec §6.5, spec-18 §7): FUND is a
			// reserved keyless class, never tx-created. Enforced here too so the invariant
			// is self-standing on the no-revalidation resync path.
			if classToStore == pb.AccountClass_ACCOUNT_CLASS_FUND {
				return errors.New("FUND is a reserved keyless class: cannot be created by a RECEIVE")
			}
		}
		// U2-registration shape mirror (forquinn item 1): its only legitimate home is a
		// GUARDED/VAULT account-opening RECEIVE — required + PoP-verified in the creating branch
		// below; content-based reject on every other shape (non-opening receives here, escrow /
		// non-guarded openings in their branches).
		if !creating && hasU2Registration(rb) {
			return errors.New("u2 registration is only valid on a guarded/vault account-opening RECEIVE")
		}

		seq = parsed.Seq
		head = txid

		// Read-modify-write: start from the existing record so a non-opening RECEIVE
		// (e.g. a SPENDING account receiving a second time) preserves its cached
		// AUTH_PUBKEY / BREAKGLASS_COMMIT and any transfer metadata. For a creating
		// account `arec` is the zero record and we register the first-block key
		// material here. Keyed accounts must never be written via the bare putAccount
		// wrapper (it drops the TLV blob).
		out := arec
		out.Head = head
		out.Balance = bal
		out.Seq = seq
		out.Class = classToStore

		if creating && classToStore == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			// Escrow opening (spec-18 §5.6.3): store the two parties' material BY VALUE (ESCROW_META),
			// re-derive + enforce the id (keys-spec §6.4 — self-standing on the no-revalidate resync
			// path), and charge the attested fee out of the credited balance. The escrow is keyless of
			// a single key — it carries NO AUTH_PUBKEY/BREAKGLASS_COMMIT TLV.
			eo := rb.GetEscrowOpen()
			if eo == nil {
				return errors.New("escrow opening: missing escrow_open")
			}
			// Mirror the validate reject: a keyless two-party escrow never registers a U2.
			if hasU2Registration(rb) {
				return errors.New("u2 registration is only valid on a guarded/vault account-opening RECEIVE")
			}
			loPub := eo.GetPartyLoPubkey().GetV()
			hiPub := eo.GetPartyHiPubkey().GetV()
			loBG := eo.GetPartyLoBreakglassCommit().GetV()
			hiBG := eo.GetPartyHiBreakglassCommit().GetV()
			if len(loPub) != crypto.HybridPubKeySize || len(hiPub) != crypto.HybridPubKeySize ||
				len(loBG) != breakglassCommitLen || len(hiBG) != breakglassCommitLen {
				return errors.New("escrow opening: malformed party material")
			}
			if bytes.Compare(loPub, hiPub) >= 0 {
				return errors.New("escrow opening: parties must be distinct and in canonical order")
			}
			// Both party pubkeys must be cryptographically parseable (resync-safe mirror of the validate
			// check), else an unparseable counterparty key could deadlock the 2-of-2.
			if _, perr := crypto.ParseHybridPubKey(loPub); perr != nil {
				return fmt.Errorf("escrow opening: party_lo pubkey not parseable: %w", perr)
			}
			if _, perr := crypto.ParseHybridPubKey(hiPub); perr != nil {
				return fmt.Errorf("escrow opening: party_hi pubkey not parseable: %w", perr)
			}
			if rec.From == nil || len(rec.From.V) != 32 {
				return errors.New("escrow opening: funding receivable has no source")
			}
			var funderID [32]byte
			copy(funderID[:], rec.From.V)
			// Funder anchor: the signing key (auth_pubkey) must be one of the two parties AND the
			// funding source's registered key. The source record is present whenever the receivable is
			// (the same SEND apply wrote both), so its absence is an invariant violation, not retryable.
			funderPub := rb.GetAuthPubkey().GetV()
			srcRec, ok := getAccountRecord(view.tx, funderID)
			if !ok {
				return fmt.Errorf("escrow opening: funding source %x not found", funderID[:4])
			}
			if len(funderPub) != crypto.HybridPubKeySize ||
				(!bytes.Equal(funderPub, loPub) && !bytes.Equal(funderPub, hiPub)) ||
				!bytes.Equal(funderPub, srcRec.AuthPubKey) {
				return errors.New("escrow opening: funder must be one of the two parties and the funding source")
			}
			want := crypto.DerivedAccountID(crypto.AccountTypeEscrow, crypto.EscrowKeyblob(loPub, hiPub), funderID, rec.FromSeq)
			if want != acct {
				return fmt.Errorf("escrow opening: account-id %x != derivation %x", acct[:4], want[:4])
			}
			out.EscrowPartyLoPub = append([]byte(nil), loPub...)
			out.EscrowPartyLoBG = append([]byte(nil), loBG...)
			out.EscrowPartyHiPub = append([]byte(nil), hiPub...)
			out.EscrowPartyHiBG = append([]byte(nil), hiBG...)
			out.EscrowTrigger = eo.GetAttestationTriggerEpoch()
			if eo.GetAttested() {
				out.EscrowFlags |= escrowFlagAttested
				// Charge the attested fee out of the credited balance (the funder paid the normal send
				// fee on the funding SEND) and credit it to the Fund. validate guaranteed bal > fee; the
				// idempotency guard at the top of ApplyTx keeps a resync re-apply from double-charging.
				if bal <= econ.AttestedEscrowFee {
					return errors.New("escrow opening: attested funding amount must exceed the attested fee")
				}
				bal -= econ.AttestedEscrowFee
				out.Balance = bal
				if err := creditFund(view.tx, fundAcct, econ.AttestedEscrowFee); err != nil {
					return err
				}
			}
		} else if creating {
			// First-block key registration (keys-spec §8.3): auth pubkey + breakglass
			// commitment, required and immutable. (Genesis/Fund are seeded out-of-band
			// and never traverse this path.)
			ap := rb.GetAuthPubkey().GetV()
			bg := rb.GetBreakglassCommitment().GetV()
			if len(ap) != crypto.HybridPubKeySize {
				return errors.New("opening RECEIVE: auth_pubkey must be present and 2625 bytes")
			}
			if len(bg) != breakglassCommitLen {
				return errors.New("opening RECEIVE: breakglass_commitment must be present and 64 bytes")
			}
			// For a TRANSFER chain the controlling keys are COPIED from a KEY SOURCE and
			// the id carries the creation nonce; load the key source's cached keys so
			// openingAccountID can enforce the copy + derivation. For an ordinary transfer
			// the key source IS the funding source (rec.From); for a Guardian-returned stake
			// (P2.3b) it is the STAKER (rec.KeySourceId), while the creator stays rec.From
			// (the keyless Fund). rec.FromSeq is the nonce. Base classes ignore these.
			var srcAuthPub, srcBg []byte
			var srcID [32]byte
			var srcClass pb.AccountClass // funding-source class (rec.From), for the attestor flag
			if classToStore == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				if rec.From == nil || len(rec.From.V) != 32 {
					return errors.New("TRANSFER receive: funding receivable has no source")
				}
				copy(srcID[:], rec.From.V)
				keySrcID := srcID
				if rec.KeySourceId != nil && len(rec.KeySourceId.V) == 32 {
					copy(keySrcID[:], rec.KeySourceId.V)
				}
				ksRec, ok := getAccountRecord(view.tx, keySrcID)
				if !ok {
					// On resync the key source's chain may not be replayed yet (for a return
					// stake the staker is independent of the Fund SEND that minted this
					// receivable, so there is no prev/recv dependency edge). Treat as retryable
					// so the apply loop defers until the key source lands. (For an ordinary
					// transfer the receivable's existence already implies the source applied, so
					// this never fires.)
					return fmt.Errorf("%w: TRANSFER receive key source %x not found", ErrUnknownStake, keySrcID[:4])
				}
				srcAuthPub, srcBg = ksRec.AuthPubKey, ksRec.BreakglassCommit
				// D2 DERIVED COPY (forquinn item 1): the chain inherits the key source's stored
				// U2 alongside the copied auth key + breakglass commitment — from COMMITTED data,
				// never carried on the opening tx (nothing carried ⇒ nothing strippable), so a
				// resync replay re-derives the identical record. The single-sig resolution then
				// accepts U1 OR U2 on the chain, and the path-(a) release verifies sig2 against
				// this copy. Empty for a U2-less key source (a TIMELOCKED source or a return-stake
				// staker), leaving those chains byte-identical to pre-forquinn.
				if len(ksRec.U2PubKey) == crypto.HybridPubKeySize {
					out.U2PubKey = append([]byte(nil), ksRec.U2PubKey...)
				}
				// The attestor flag keys off the FUNDING SOURCE's (rec.From) class, NOT the key
				// source's: for an ordinary transfer they coincide (so reuse ksRec); for a
				// Guardian-returned stake the source is the keyless Fund (class FUND → flag unset)
				// while the key source is the staker. The source record is always present here (an
				// ordinary transfer's receivable implies its source applied; a return's source is
				// the genesis-seeded Fund).
				if keySrcID == srcID {
					srcClass = ksRec.Class
				} else if sr, ok := getAccountRecord(view.tx, srcID); ok {
					srcClass = sr.Class
				}
			}
			// Re-derive and enforce the account-id here too (keys-spec §6.4). The same
			// check runs in ValidateTxAgainstSnapshot, but resync replays committed
			// blocks straight through ApplyTx WITHOUT re-validating, so enforcing it
			// here makes the id invariant self-standing rather than resting solely on
			// the post-rebuild frontier-root comparison. creatorID = srcID (rec.From).
			want, err := openingAccountID(classToStore, ap, bg, srcAuthPub, srcBg, srcID, rec.FromSeq)
			if err != nil {
				return err
			}
			if want != acct {
				return fmt.Errorf("opening RECEIVE: account-id %x != derivation %x", acct[:4], want[:4])
			}
			// GUARDED/VAULT opening mirror (forquinn item 1): re-verify the FULL U2 registration
			// (lengths, != U1, PoP over m_u2) from the committed tx bytes and cache the key —
			// resync replays without validate, so the registered-U2 invariant must be
			// self-standing here, exactly like the id re-derivation above. Every other base
			// class rejects a carried U2 block (content-based).
			if classRequiresU2(classToStore) {
				u2pub, uerr := verifyU2Registration(rb, acct, ap)
				if uerr != nil {
					return uerr
				}
				out.U2PubKey = append([]byte(nil), u2pub...)
			} else if hasU2Registration(rb) {
				return errors.New("u2 registration is only valid on a guarded/vault account-opening RECEIVE")
			}
			out.AuthPubKey = append([]byte(nil), ap...)
			out.BreakglassCommit = append([]byte(nil), bg...)

			// For a TRANSFER chain creation, store the immutable transfer metadata from
			// committed data: destination & unlock from the signed tx body, source from
			// the funding receivable (validated above). Never recomputed (resync-safe).
			if classToStore == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				if rb.TransferDestination == nil || len(rb.TransferDestination.V) != 32 {
					return errors.New("TRANSFER receive missing transfer_destination")
				}
				copy(out.TransferSource[:], srcID[:])
				copy(out.TransferDest[:], rb.TransferDestination.V)
				out.TransferUnlock = rb.TransferUnlockEpoch
				// release_requires_attestor (spec-18 §3.3, spec-19 §6.1): set iff the funding
				// SOURCE is GUARDED/VAULT, so the chain's release-to-dest needs the flat M-of-N
				// attestor quorum. Derived purely from committed data (the source's immutable
				// class) so a resync replay re-derives the identical flag. `out` starts from the
				// zero record for a creating account, so the bit is 0 unless set here.
				if sourceClassRequiresAttestor(srcClass) {
					out.TransferFlags |= transferFlagReleaseRequiresAttestor
				}
				// Breakglass-origin chain (P5.1, spec-19 §6.4): derived from the funding receivable's
				// from_breakglass marker (set when the funding SEND revealed the source's breakglass key).
				// A breakglass chain ALWAYS needs the attestor quorum on release (even from a SPENDING
				// source) and its release controlling-key may be the revealed breakglass key (bit 1).
				// Derived from committed data, so resync re-derives the identical flags.
				if rec.FromBreakglass {
					out.TransferFlags |= transferFlagReleaseRequiresAttestor
					out.TransferFlags |= transferFlagBreakglassOrigin
				}
				// P5.5: store the threaded return-deposit link IMMUTABLY on a Fund-sourced return-stake
				// chain, from the funding receivable's return_deposit_txid (committed data → resync re-derives
				// the identical value). A later breakglass-RETURN of this chain to the Fund reads it to mark
				// the BFundStakes row Reverted. Zero (tag absent) on every ordinary transfer chain.
				if rdt := rec.GetReturnDepositTxid().GetV(); len(rdt) == 32 {
					copy(out.TransferReturnDepositTxid[:], rdt)
				}
			}
		}
		if err := putAccountRecord(view.tx, acct, out); err != nil {
			return err
		}
		return putTxRaw(view.tx, txid, raw)

	default:
		return ErrWrongType
	}
}

type bboltTxView struct{ tx *bbolt.Tx }
