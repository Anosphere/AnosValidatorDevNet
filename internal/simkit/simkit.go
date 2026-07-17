// Package simkit holds shared helpers for the command-line simulators after the
// P1.2 post-quantum cutover. The sims used to be ed25519 with "account-id == raw
// pubkey"; now every account is a HYBRID keypair (ML-DSA-87 + P-256) whose 32-byte
// account-id is HASH-DERIVED from the pubkey (keys-spec §6), and the bulky pubkey
// plus a breakglass commitment are registered on the account's opening RECEIVE.
//
// To keep that ceremony in one place (and out of a dozen near-identical mains) this
// package provides:
//   - Account: a seed-derived hybrid account (auth + breakglass keys, derived id,
//     breakglass commitment) — the seed is the small, env-pinnable secret.
//   - Tx builders for SEND / opening-RECEIVE / RECEIVE that fill in the new
//     registration fields and sign with the hybrid auth key.
//   - Client: thin HTTP helpers (submit / account / receivables + polling) ported
//     from the old per-sim copies.
package simkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// Account is a hybrid-keyed simulator account: an auth keypair and a breakglass
// keypair, both deterministically derived from 32-byte seeds (so the public half
// and the account-id are reproducible from the seed alone), plus the derived
// account-id and the 64-byte breakglass commitment.
//
// A base account's id is BaseAccountID(class, authPub) — base accounts have fresh
// keys. A TRANSFER chain is NOT fresh: it copies its funding source's auth+breakglass
// keys and its id is the creation-nonce DerivedAccountID (see DerivedTransferAccount,
// P1.3). The breakglass key is registered (as a commitment) but never exercised until
// P5.
type Account struct {
	Class  pb.AccountClass
	priv   *crypto.HybridPrivateKey
	pub    *crypto.HybridPubKey
	bgPriv *crypto.HybridPrivateKey // breakglass (set 2 / backup) key — exercised only by a breakglass move (P5.1)
	bgPub  *crypto.HybridPubKey
	// u2Priv/u2Pub are the OPTIONAL second user key U2 (forquinn item 1) — registered on a
	// GUARDED/VAULT opening via BuildGuardedOpeningReceive and copied onto derived TRANSFER
	// chains (the validator does the same by derived copy, D2). nil for every account that never
	// attached one; every helper is nil-safe, so pre-U2 sims are untouched.
	u2Priv *crypto.HybridPrivateKey
	u2Pub  *crypto.HybridPubKey
	ID     [32]byte
	Commit []byte // 64-byte SHA-512 breakglass commitment (class-independent since P5.2)
}

// NewAccount derives a hybrid account from an auth seed and a breakglass seed.
func NewAccount(class pb.AccountClass, authSeed, bgSeed [32]byte) *Account {
	priv, pub := crypto.GenerateHybridKeyFromSeed(authSeed)
	bgPriv, bgPub := crypto.GenerateHybridKeyFromSeed(bgSeed)
	tb := crypto.AccountTypeByteForClass(class)
	commit := crypto.BreakglassCommitment(bgPub.Encode())
	a := &Account{Class: class, priv: priv, pub: pub, bgPriv: bgPriv, bgPub: bgPub}
	a.ID = crypto.BaseAccountID(tb, pub.Encode())
	a.Commit = append([]byte(nil), commit[:]...)
	return a
}

// RandomAccount derives an account from fresh random seeds (for ephemeral test
// participants the sim does not need to persist).
func RandomAccount(class pb.AccountClass) *Account {
	return NewAccount(class, RandSeed(), RandSeed())
}

// AttachU2 derives the account's second user key U2 from a seed (forquinn item 1). Call it on a
// GUARDED/VAULT account BEFORE BuildGuardedOpeningReceive — the opening registers U2 with a
// proof-of-possession. Returns the account for chaining. The account-id is NOT affected (U2 is
// deliberately outside the id derivation).
func (a *Account) AttachU2(u2Seed [32]byte) *Account {
	a.u2Priv, a.u2Pub = crypto.GenerateHybridKeyFromSeed(u2Seed)
	return a
}

// HasU2 reports whether a U2 keypair is attached.
func (a *Account) HasU2() bool { return a.u2Pub != nil }

// U2PubKeyBytes returns the canonical 2625-byte U2 pubkey, or nil when no U2 is attached.
func (a *Account) U2PubKeyBytes() []byte {
	if a.u2Pub == nil {
		return nil
	}
	return a.u2Pub.Encode()
}

// SignWithU2 signs tx's single signature slot (Tx.sig) with the account's U2 key — a
// single-user-signature operation exercised as U2 (hop-1 initiate, owner-cancel, or the path-(b)
// user half; the validator accepts U1 OR U2 there). Errors if no U2 is attached.
func (a *Account) SignWithU2(tx *pb.Tx) error {
	if a.u2Priv == nil {
		return fmt.Errorf("account has no U2 key attached")
	}
	return crypto.SignTxHybrid(tx, a.u2Priv)
}

// DerivedTransferAccount builds the TRANSFER chain spawned when `source` sends to it
// (P1.3, keys-spec §6.2). The chain is NOT a fresh account: it shares the source's
// auth keypair (so the source's normal key controls it — return-to-source is the owner
// cancel) and copies the source's 64-byte breakglass commitment, and its 32-byte id is
// the creation-nonce DerivedAccountID(TRANSFER, source_auth_pubkey, source_id,
// sourceSendSeq). sourceSendSeq is the seq of the source SEND that funds the chain —
// the validator independently derives the same id from the funding receivable's
// from_seq, so the caller MUST send with exactly this seq. Signing the chain's opening
// RECEIVE and its drain therefore uses the source's key (shared priv).
func DerivedTransferAccount(source *Account, sourceSendSeq uint64) *Account {
	id := crypto.DerivedAccountID(crypto.AccountTypeTransfer, source.pub.Encode(), source.ID, sourceSendSeq)
	return &Account{
		Class:  pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		priv:   source.priv,
		pub:    source.pub,
		bgPriv: source.bgPriv, // the chain copies the source's breakglass key (recovery flows through it)
		bgPub:  source.bgPub,
		u2Priv: source.u2Priv, // the chain inherits the source's U2 by derived copy (D2; nil-safe)
		u2Pub:  source.u2Pub,
		ID:     id,
		Commit: append([]byte(nil), source.Commit...),
	}
}

// IDBytes returns the 32-byte account-id as a slice copy.
func (a *Account) IDBytes() []byte { return append([]byte(nil), a.ID[:]...) }

// AccountID returns the account-id wrapped for proto use.
func (a *Account) AccountID() *pb.AccountId { return &pb.AccountId{V: a.IDBytes()} }

// AuthPubKeyHex returns the canonical hybrid auth pubkey as hex (for env pinning).
func (a *Account) AuthPubKeyHex() string { return hex.EncodeToString(a.pub.Encode()) }

// AuthPubKeyBytes returns the canonical 2625-byte hybrid auth pubkey (e.g. to seed a snapshot's
// cached AUTH_PUBKEY in tests).
func (a *Account) AuthPubKeyBytes() []byte { return a.pub.Encode() }

// Sign signs tx with the account's hybrid auth key, setting tx.Sig.
func (a *Account) Sign(tx *pb.Tx) error { return crypto.SignTxHybrid(tx, a.priv) }

// MustSign signs or panics.
func (a *Account) MustSign(tx *pb.Tx) {
	if err := a.Sign(tx); err != nil {
		panic(fmt.Sprintf("sign: %v", err))
	}
}

// BreakglassPubBytes returns the account's 2625-byte breakglass (set 2) hybrid pubkey.
func (a *Account) BreakglassPubBytes() []byte { return a.bgPub.Encode() }

// EscrowBreakglassCommit returns this account's breakglass commitment for storage in an escrow slot,
// so the party can later satisfy that slot with its revealed breakglass key. Since P5.2 the
// commitment carries no type byte, so this is byte-identical to the account's own-class Commit
// (escrow option-B collapsed — a party reuses one backup key/commitment everywhere). Kept as a named
// helper for call-site clarity at escrow openings.
func (a *Account) EscrowBreakglassCommit() []byte {
	c := crypto.BreakglassCommitment(a.bgPub.Encode())
	return append([]byte(nil), c[:]...)
}

// SignBreakglass authorizes a breakglass move (P5.1): it sets tx.revealed_breakglass_pubkey to the
// account's breakglass pubkey and signs Tx.sig with the breakglass key. The reveal is set BEFORE
// signing so it is folded into the preimage (SignBytesACTE), binding it to both the signature and
// the txid. Used for the hop-1 source drain, the chain's opening RECEIVE, and the hop-2 release.
func (a *Account) SignBreakglass(tx *pb.Tx) error {
	tx.RevealedBreakglassPubkey = &pb.HybridPubKey{V: a.bgPub.Encode()}
	return crypto.SignTxHybrid(tx, a.bgPriv)
}

// MustSignBreakglass signs with the breakglass key or panics.
func (a *Account) MustSignBreakglass(tx *pb.Tx) {
	if err := a.SignBreakglass(tx); err != nil {
		panic(fmt.Sprintf("sign breakglass: %v", err))
	}
}

// BuildSend builds an unsigned SEND extending the account's chain. prevHead/seq
// come from the sender's current AccountState (prev = head, seq = state.seq + 1).
// The SEND's account_class is the sender's class (validators derive the recipient
// routing restriction from it).
func BuildSend(from *Account, prevHead [32]byte, seq uint64, to [32]byte, amount, fee uint64) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: from.AccountID(),
		Prev:    hash32(prevHead),
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:       amount,
			Fee:          fee,
			AccountClass: from.Class,
		}},
	}
}

// BuildStakeSend builds an unsigned stake-deposit SEND (to == Fund id) carrying the P2.2
// stake metadata (staked_for / time_delay / proof_pointer). It is otherwise an ordinary
// SEND, so the Fund credits the amount (Alt A) and the validator appends a reference-table
// row. A restricted-class account cannot stake directly (require-routing): build the SEND
// from a SPENDING account, or drain a TRANSFER chain to the Fund (the chain's `from` is the
// TRANSFER account; attribution follows its stored source).
func BuildStakeSend(from *Account, prevHead [32]byte, seq uint64, fund [32]byte, amount, fee uint64, stakedFor string, delay pb.StakeTimeDelay, proofPointer []byte) *pb.Tx {
	tx := BuildSend(from, prevHead, seq, fund, amount, fee)
	s := tx.GetSend()
	s.StakedFor = stakedFor
	s.TimeDelay = delay
	if len(proofPointer) > 0 {
		s.ProofPointer = append([]byte(nil), proofPointer...)
	}
	return tx
}

// BuildBankerStakeSend builds a Banker stake/rotation deposit (P4.1, spec-18 §3.7): a stake SEND to
// the Fund tagged "banker" that additionally carries the validator's consensus P-256 key (33-byte
// compressed) + endpoint — the descriptor the Fund-derived validator set reads (last-write-wins by
// send-seq). Banker min-lock is 1 month. Sign with the staking account. A small additive deposit with
// a fresh key/endpoint is the P4.2 rotation path.
func BuildBankerStakeSend(from *Account, prevHead [32]byte, seq uint64, fund [32]byte, amount, fee uint64, delay pb.StakeTimeDelay, consensusPubkey []byte, endpoint string) *pb.Tx {
	tx := BuildStakeSend(from, prevHead, seq, fund, amount, fee, "banker", delay, nil)
	s := tx.GetSend()
	s.ConsensusPubkey = append([]byte(nil), consensusPubkey...)
	s.Endpoint = endpoint
	return tx
}

// RandomConsensusKey returns a fresh 33-byte compressed P-256 public key (a stand-in for a validator's
// consensus id), for banker stake/rotation deposits in the sims.
func RandomConsensusKey() []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	c := crypto.CompressP256PublicKey(&priv.PublicKey)
	return append([]byte(nil), c[:]...)
}

// BuildFundSend builds an unsigned Fund SEND (P2.3, spec-19 §6.2): a SEND whose account IS
// the keyless Fund, authorized by a weighted-Guardian HybridMultiSig instead of a single
// Tx.sig. account_class is FUND, fee is 0 (Fund SENDs are zero-fee), and fund_send_epoch names
// the epoch the Guardian signers vouch for (each becomes active at it on apply; must be <= the
// finalizing epoch). prevHead/seq come from the Fund's current AccountState. Sign it with
// SignFundSend, NOT Account.Sign.
func BuildFundSend(fund [32]byte, prevHead [32]byte, seq uint64, to [32]byte, amount, fundSendEpoch uint64) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), fund[:]...)},
		Prev:    hash32(prevHead),
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:            &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:        amount,
			Fee:           0,
			AccountClass:  pb.AccountClass_ACCOUNT_CLASS_FUND,
			FundSendEpoch: fundSendEpoch,
		}},
	}
}

// SignFundSend assembles the verify-only Guardian multisig on a Fund SEND: each signer signs
// the tx digest m = SHA-256(SignBytesACTE(tx)) with its hybrid auth key, and the entry carries
// the signer's account-id + that signature (spec-19 §4). The tx body (incl. fund_send_epoch)
// must be final before calling — the multisig is NOT part of m. Sets tx.MultiSig.
func SignFundSend(tx *pb.Tx, signers []*Account) error {
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		return err
	}
	ms := &pb.HybridMultiSig{}
	for _, s := range signers {
		sig, err := s.priv.Sign(m)
		if err != nil {
			return err
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId: s.AccountID(),
			Sig:      &pb.HybridSig{V: sig.Encode()},
		})
	}
	tx.MultiSig = ms
	return nil
}

// SignAttestorRelease signs an attestor-gated TRANSFER release-to-dest (P3.2, spec-19 §6.1,
// forquinn path (b)): it stamps the mandatory case commitment (forquinn item 2) onto the SEND
// body, then the chain's controlling key sets Tx.sig AND each Fund Attestor co-signs the SAME
// digest m = SHA-256(SignBytesACTE(tx)) into Tx.MultiSig. The case fields are set FIRST — they
// are folded into the preimage, so m (and therefore every signature) commits to them. Both
// halves sign m (the multisig is NOT part of m), so order is irrelevant; the release needs the
// chain's Tx.sig, >= ATTESTOR_QUORUM_M verifying attestor signatures, AND both 32-byte case
// fields. `chain` is the TRANSFER chain account (it shares the GUARDED/VAULT source's copied
// key); `attestors` are the signing Attestor identities. The rest of the tx body must be final
// before calling.
func SignAttestorRelease(tx *pb.Tx, chain *Account, attestors []*Account, caseNonce, attestationHash [32]byte) error {
	SetCaseCommitment(tx, caseNonce, attestationHash)
	if err := chain.Sign(tx); err != nil {
		return err
	}
	return SignFundSend(tx, attestors) // assembles the multisig over m; sets tx.MultiSig
}

// BuildFundReturnSend builds a Guardian-authorized return-stake Fund SEND (P2.3b): a Fund SEND
// whose `to` is the staker-keyed return-transfer-chain id (see DerivedReturnChain), carrying the
// returned stake's deposit_txid and the staked amount. Sign with SignFundSend.
func BuildFundReturnSend(fund, prevHead [32]byte, seq uint64, chainID [32]byte, amount, fundEpoch uint64, depositTxid [32]byte) *pb.Tx {
	tx := BuildFundSend(fund, prevHead, seq, chainID, amount, fundEpoch)
	tx.GetSend().ReturnDepositTxid = &pb.Hash32{V: append([]byte(nil), depositTxid[:]...)}
	return tx
}

// BuildFundKickSend builds a Guardian-authorized kick Fund SEND (P2.3b): a Fund SEND to the Fund
// itself (zero amount) that forfeits the stake at deposit_txid. Sign with SignFundSend.
func BuildFundKickSend(fund, prevHead [32]byte, seq, fundEpoch uint64, depositTxid [32]byte) *pb.Tx {
	tx := BuildFundSend(fund, prevHead, seq, fund, 0, fundEpoch)
	tx.GetSend().ReturnDepositTxid = &pb.Hash32{V: append([]byte(nil), depositTxid[:]...)}
	return tx
}

// SignStakeOwnerAuth builds the P5.4 owner authorization: the current stake owner signs the recovery
// binding m_owner = StakeOwnerAuthDigest(op, depositTxid, beneficiary). With useBreakglass it reveals the
// owner's breakglass key and signs with THAT (recovery when the auth key is lost); otherwise it signs
// with the owner's normal auth key. Attach the result to tx.GetSend().OwnerAuth BEFORE SignFundSend —
// owner_auth is folded into the Guardian-signed preimage. op = crypto.StakeOwnerAuthOp{Return,Reattribute}.
func (a *Account) SignStakeOwnerAuth(op byte, depositTxid, beneficiary [32]byte, useBreakglass bool) *pb.StakeOwnerAuth {
	m := crypto.StakeOwnerAuthDigest(op, depositTxid, beneficiary)
	oa := &pb.StakeOwnerAuth{}
	priv := a.priv
	if useBreakglass {
		priv = a.bgPriv
		oa.RevealedBreakglassPubkey = &pb.HybridPubKey{V: a.bgPub.Encode()}
	}
	sig, err := priv.Sign(m)
	if err != nil {
		panic(fmt.Sprintf("sign owner_auth: %v", err))
	}
	oa.Sig = &pb.HybridSig{V: sig.Encode()}
	return oa
}

// BuildFundReattributeSend builds a P5.4b C1 re-attribution Fund SEND: a Fund→Fund send (amount 0) that
// re-points the stake at deposit_txid to a new owner B, keeping it staked. Carries the current owner's
// owner_auth (op = re-attribute) and — for a BANKER stake — the validator descriptor B inherits
// (consensusKey + endpoint). Sign with SignFundSend.
func BuildFundReattributeSend(fund, prevHead [32]byte, seq, fundEpoch uint64, depositTxid, beneficiary [32]byte, consensusKey []byte, endpoint string, ownerAuth *pb.StakeOwnerAuth) *pb.Tx {
	tx := BuildFundSend(fund, prevHead, seq, fund, 0, fundEpoch)
	s := tx.GetSend()
	s.ReturnDepositTxid = &pb.Hash32{V: append([]byte(nil), depositTxid[:]...)}
	s.RecoveryBeneficiary = &pb.AccountId{V: append([]byte(nil), beneficiary[:]...)}
	s.OwnerAuth = ownerAuth
	if len(consensusKey) > 0 {
		s.ConsensusPubkey = append([]byte(nil), consensusKey...)
		s.Endpoint = endpoint
	}
	return tx
}

// BuildFundGeneralizedReturnSend builds a P5.4 C2 generalized-return Fund SEND: a return whose opening
// TRANSFER chain copies the BENEFICIARY B's keys (not the staker's) and locks for the Guardian-chosen
// return_delay_epochs, carrying the stake owner's owner_auth. chainID must be DerivedReturnChain(B, fund,
// seq).ID. A nil ownerAuth (e.g. B == staker) makes this a normal return with an explicit delay. Sign
// with SignFundSend.
func BuildFundGeneralizedReturnSend(fund, prevHead [32]byte, seq uint64, chainID [32]byte, amount, fundEpoch uint64, depositTxid, beneficiary [32]byte, delayEpochs uint64, ownerAuth *pb.StakeOwnerAuth) *pb.Tx {
	tx := BuildFundReturnSend(fund, prevHead, seq, chainID, amount, fundEpoch, depositTxid)
	s := tx.GetSend()
	s.RecoveryBeneficiary = &pb.AccountId{V: append([]byte(nil), beneficiary[:]...)}
	s.ReturnDelayEpochs = delayEpochs
	s.OwnerAuth = ownerAuth
	return tx
}

// DerivedReturnChain builds the TRANSFER chain a return-stake Fund SEND opens (P2.3b): it COPIES
// the staker's auth+breakglass keys (so the staker controls it) but its id is created by the
// keyless Fund — DerivedAccountID(TRANSFER, staker auth pubkey, fundID, fundSendSeq) — so it
// cannot collide with a staker-originated transfer at the same nonce. fundSendSeq is the seq of
// the authorizing Fund SEND.
func DerivedReturnChain(staker *Account, fundID [32]byte, fundSendSeq uint64) *Account {
	id := crypto.DerivedAccountID(crypto.AccountTypeTransfer, staker.pub.Encode(), fundID, fundSendSeq)
	return &Account{
		Class:  pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		priv:   staker.priv,
		pub:    staker.pub,
		bgPriv: staker.bgPriv,
		bgPub:  staker.bgPub,
		u2Priv: staker.u2Priv, // derived copy of the key source's U2 (D2; nil-safe)
		u2Pub:  staker.u2Pub,
		ID:     id,
		Commit: append([]byte(nil), staker.Commit...),
	}
}

// --------------------
// Escrow (P3.3, spec-18 §5.6 / spec-19 §6.3)
// --------------------

// EscrowAccount is a two-party escrow: the keyless ESCROW account-id plus the two party
// Accounts (in canonical order Lo.pub < Hi.pub — the same order crypto.EscrowKeyblob /
// the ESCROW_META record use) and the Funder (one of the two parties, who signs the opening
// alone). The escrow holds no key of its own — outflow is the 2-of-2 (or 1-of-2 trigger) of
// the two parties' hybrid keys.
type EscrowAccount struct {
	ID     [32]byte
	Lo, Hi *Account // canonical-sorted parties (Lo.pub < Hi.pub)
	Funder *Account // one of Lo/Hi — the account whose SEND funds + opens the escrow
}

// DerivedEscrowAccount builds the escrow spawned when `funder` sends to it (keys-spec §6.2).
// The two parties are sorted into canonical order; the id is
// DerivedAccountID(ESCROW, EscrowKeyblob(lo,hi), funder.ID, funderSendSeq). funderSendSeq is
// the seq of the funder SEND that funds the escrow — the validator independently derives the
// same id from the funding receivable's from_seq, so the caller MUST send with exactly this seq.
// `funder` must be one of partyA/partyB.
func DerivedEscrowAccount(partyA, partyB, funder *Account, funderSendSeq uint64) *EscrowAccount {
	lo, hi := partyA, partyB
	if bytes.Compare(lo.pub.Encode(), hi.pub.Encode()) > 0 {
		lo, hi = hi, lo
	}
	keyblob := crypto.EscrowKeyblob(lo.pub.Encode(), hi.pub.Encode())
	id := crypto.DerivedAccountID(crypto.AccountTypeEscrow, keyblob, funder.ID, funderSendSeq)
	return &EscrowAccount{ID: id, Lo: lo, Hi: hi, Funder: funder}
}

// IDBytes returns the escrow's 32-byte account-id as a slice copy.
func (e *EscrowAccount) IDBytes() []byte { return append([]byte(nil), e.ID[:]...) }

// BuildEscrowOpening builds the funder-signed opening RECEIVE that claims `rid` and registers
// the escrow (spec-18 §5.6.3). It carries the funder's signing key in auth_pubkey and BOTH
// parties' material (canonical-ordered) in escrow_open. trigger is the attestation_trigger_epoch
// (>= creation + ESCROW_ATTESTATION_DELAY_EPOCHS); attested sets the attested-escrow flag (charges
// ATTESTED_ESCROW_FEE at funding). Sign it with the funder (e.Funder.Sign).
func BuildEscrowOpening(e *EscrowAccount, rid [32]byte, trigger uint64, attested bool) *pb.Tx {
	body := &pb.TxBodyReceive{
		ReceivableId: hash32(rid),
		AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
		AuthPubkey:   &pb.HybridPubKey{V: e.Funder.pub.Encode()}, // funder's signing key
		EscrowOpen: &pb.EscrowOpen{
			PartyLoPubkey: &pb.HybridPubKey{V: e.Lo.pub.Encode()},
			// Each party's breakglass commitment is stored under the ESCROW type byte (option B, P5.1),
			// NOT the party's own-class commit, so the breakglass-slot verify re-derives with the escrow's
			// own (known) class.
			PartyLoBreakglassCommit: &pb.Hash64{V: e.Lo.EscrowBreakglassCommit()},
			PartyHiPubkey:           &pb.HybridPubKey{V: e.Hi.pub.Encode()},
			PartyHiBreakglassCommit: &pb.Hash64{V: e.Hi.EscrowBreakglassCommit()},
			AttestationTriggerEpoch: trigger,
			Attested:                attested,
		},
	}
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: e.IDBytes()},
		Prev:    hash32([32]byte{}),
		Seq:     1,
		Body:    &pb.Tx_Receive{Receive: body},
	}
}

// BuildEscrowOutflow builds an unsigned keyless escrow outflow SEND (full-balance, zero-fee) to
// `to`. account_class is ESCROW; it carries no Tx.sig — the authorization is the multisig set by
// SignEscrowOutflow. prevHead/seq come from the escrow's current AccountState.
func BuildEscrowOutflow(e *EscrowAccount, prevHead [32]byte, seq uint64, to [32]byte, amount uint64) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: e.IDBytes()},
		Prev:    hash32(prevHead),
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:       amount,
			Fee:          0,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
		}},
	}
}

// SignEscrowOutflow assembles the escrow 2-of-2 (or 1-of-2 trigger) multisig: each signer signs the
// tx digest m = SHA-256(SignBytesACTE(tx)) with its hybrid auth key, and the entry carries the
// signer's account-id + signature (spec-19 §6.3). Pass BOTH parties for a 2-of-2; pass ONE party for
// the attested 1-of-2 → Fund trigger (or to exercise a rejected 1-of-1). The tx body must be final
// before calling. Sets tx.MultiSig. (Shares the assembly with SignFundSend — the carrier is identical.)
func SignEscrowOutflow(tx *pb.Tx, signers []*Account) error {
	return SignFundSend(tx, signers)
}

// SignEscrowOutflowWith assembles an escrow outflow multisig where `normal` parties sign with their
// auth key and `breakglass` parties sign with their REVEALED breakglass key (P5.1, spec-19 §6.3):
// each breakglass entry carries revealed_breakglass_pubkey, and the validator checks the key's
// ESCROW-type commitment against the party's stored slot commitment. Both kinds sign the same digest
// m = SHA-256(SignBytesACTE(tx)) (the entries are not part of m). Sets tx.MultiSig.
func SignEscrowOutflowWith(tx *pb.Tx, normal, breakglass []*Account) error {
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		return err
	}
	ms := &pb.HybridMultiSig{}
	for _, s := range normal {
		sig, err := s.priv.Sign(m)
		if err != nil {
			return err
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId: s.AccountID(),
			Sig:      &pb.HybridSig{V: sig.Encode()},
		})
	}
	for _, s := range breakglass {
		sig, err := s.bgPriv.Sign(m)
		if err != nil {
			return err
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId:                 s.AccountID(),
			Sig:                      &pb.HybridSig{V: sig.Encode()},
			RevealedBreakglassPubkey: &pb.HybridPubKey{V: s.bgPub.Encode()},
		})
	}
	tx.MultiSig = ms
	return nil
}

// SignBreakglassRelease signs a breakglass TRANSFER-chain release-to-dest (P5.1, spec-19 §6.4): it
// stamps the mandatory case commitment (forquinn item 2 — the breakglass hop-2 flows through the
// same attestor path (b) as a guarded/vault release), then the chain's REVEALED breakglass key sets
// Tx.sig + tx.revealed_breakglass_pubkey (the recoverer who lost the auth key), AND each Fund
// Attestor co-signs the same digest into Tx.MultiSig (the release gate). The case fields and the
// reveal are both folded into the preimage, so Tx.sig and the attestor sigs are over a digest that
// already commits to them. `chain` shares the source's copied breakglass key. The rest of the tx
// body must be final before calling.
func SignBreakglassRelease(tx *pb.Tx, chain *Account, attestors []*Account, caseNonce, attestationHash [32]byte) error {
	SetCaseCommitment(tx, caseNonce, attestationHash)
	if err := chain.SignBreakglass(tx); err != nil {
		return err
	}
	return SignFundSend(tx, attestors)
}

// BuildOpeningReceive builds an unsigned account-opening RECEIVE (seq 1, zero
// prev) that registers the account's hybrid auth pubkey + breakglass commitment.
// For a TRANSFER chain, pass transferDest/transferUnlock; otherwise nil/0.
func BuildOpeningReceive(acct *Account, rid [32]byte, transferDest *[32]byte, transferUnlock uint64) *pb.Tx {
	body := &pb.TxBodyReceive{
		ReceivableId:         hash32(rid),
		AccountClass:         acct.Class,
		AuthPubkey:           &pb.HybridPubKey{V: acct.pub.Encode()},
		BreakglassCommitment: &pb.Hash64{V: append([]byte(nil), acct.Commit...)},
	}
	if acct.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER && transferDest != nil {
		body.TransferDestination = &pb.AccountId{V: append([]byte(nil), transferDest[:]...)}
		body.TransferUnlockEpoch = transferUnlock
	}
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: acct.AccountID(),
		Prev:    hash32([32]byte{}),
		Seq:     1,
		Body:    &pb.Tx_Receive{Receive: body},
	}
}

// BuildGuardedOpeningReceive builds the unsigned account-opening RECEIVE of a GUARDED or VAULT
// account (forquinn item 1): an ordinary opening (auth pubkey + breakglass commitment) that
// additionally registers the account's second user key via a U2Registration block — the U2 pubkey
// plus U2's proof-of-possession signature over
// m_u2 = crypto.U2RegistrationDigest(account_id, u2_pubkey) (D12). AttachU2 must have been called;
// sign the result with the OWNER's U1 key (acct.Sign) — the opening is always U1-signed.
func BuildGuardedOpeningReceive(acct *Account, rid [32]byte) (*pb.Tx, error) {
	if acct.u2Priv == nil {
		return nil, fmt.Errorf("guarded/vault opening needs a U2 key: call AttachU2 first")
	}
	u2pub := acct.u2Pub.Encode()
	m, err := crypto.U2RegistrationDigest(acct.ID, u2pub)
	if err != nil {
		return nil, err
	}
	pop, err := acct.u2Priv.Sign(m)
	if err != nil {
		return nil, err
	}
	tx := BuildOpeningReceive(acct, rid, nil, 0)
	tx.GetReceive().U2 = &pb.U2Registration{
		Pubkey: &pb.HybridPubKey{V: u2pub},
		PopSig: &pb.HybridSig{V: pop.Encode()},
	}
	return tx, nil
}

// SignPathARelease signs an attestor-FREE release-to-dest on a guarded/vault-spawned TRANSFER
// chain (forquinn item 1, path (a)): both user keys instead of the attestor quorum. Fixed roles
// (D5): Tx.sig is U1 (the chain's copied auth key) and Tx.sig2 is U2 (the chain's copied second
// key), both over the same digest m = SHA-256(SignBytesACTE(tx)) — sig2 is not part of m, exactly
// like Tx.sig. No multisig, no case fields on a path-(a) release. The tx body must be final.
func SignPathARelease(tx *pb.Tx, chain *Account) error {
	if chain.u2Priv == nil {
		return fmt.Errorf("path (a) release needs the chain's U2 key: source had none attached")
	}
	if err := chain.Sign(tx); err != nil { // U1 → Tx.sig
		return err
	}
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		return err
	}
	sig2, err := chain.u2Priv.Sign(m)
	if err != nil {
		return err
	}
	tx.Sig2 = &pb.HybridSig{V: sig2.Encode()}
	return nil
}

// SetCaseCommitment sets the attestor case commitment (forquinn item 2) on a SEND body: the
// moderation case_nonce and the attestation-document hash every attestor-gated release must carry.
// Call it BEFORE signing — both fields are folded into the signed preimage, so the user signature
// and every attestor signature commit to them. Only attestor-gated releases (path (b) and the
// breakglass hop-2) may carry them; the validator rejects them anywhere else.
func SetCaseCommitment(tx *pb.Tx, caseNonce, attestationHash [32]byte) {
	s := tx.GetSend()
	s.CaseNonce = append([]byte(nil), caseNonce[:]...)
	s.AttestationHash = append([]byte(nil), attestationHash[:]...)
}

// BuildReceive builds an unsigned non-opening RECEIVE (claiming a further
// receivable on an already-established account). It carries NO registration fields
// (validators reject those on non-opening blocks).
func BuildReceive(acct *Account, prevHead [32]byte, seq uint64, rid [32]byte) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: acct.AccountID(),
		Prev:    hash32(prevHead),
		Seq:     seq,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: hash32(rid),
			AccountClass: acct.Class,
		}},
	}
}

func hash32(b [32]byte) *pb.Hash32 { return &pb.Hash32{V: append([]byte(nil), b[:]...)} }

// --------------------
// Seeds
// --------------------

// RandSeed draws a fresh 32-byte seed from crypto/rand.
func RandSeed() [32]byte {
	var s [32]byte
	if _, err := io.ReadFull(rand.Reader, s[:]); err != nil {
		panic(err)
	}
	return s
}

// SeedFromHex parses a 32-byte (64-hex-char) seed.
func SeedFromHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("seed must be 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// MustSeedFromHex parses a seed or panics.
func MustSeedFromHex(s string) [32]byte {
	seed, err := SeedFromHex(s)
	if err != nil {
		panic(err)
	}
	return seed
}

// --------------------
// HTTP client
// --------------------

// Client posts to one or more validator base URLs. Submits go to every URL (so the
// tx propagates immediately rather than waiting on gossip); queries use the first.
type Client struct {
	URLs []string
	HTTP *http.Client
}

// NewClient builds a Client from a comma-separated URL list.
func NewClient(urlCSV string) *Client {
	var urls []string
	for _, u := range strings.Split(urlCSV, ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, strings.TrimRight(u, "/"))
		}
	}
	return &Client{URLs: urls, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Submit signs nothing — the tx must already be signed — and posts it to every URL.
// It returns the first error encountered, or nil if at least one validator accepted.
func (c *Client) Submit(tx *pb.Tx) error {
	req := &pb.SubmitTxRequest{Tx: tx}
	var firstErr error
	accepted := false
	for _, u := range c.URLs {
		resp := &pb.SubmitTxResponse{}
		if err := c.postProto(u+"/submit", req, resp); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !resp.Ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("submit rejected: %v", resp.Error)
			}
			continue
		}
		accepted = true
	}
	if accepted {
		return nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no validator URLs configured")
	}
	return firstErr
}

// MustSubmit submits or panics.
func (c *Client) MustSubmit(tx *pb.Tx) {
	if err := c.Submit(tx); err != nil {
		panic(err)
	}
}

// GetAccount returns the account state from the first URL.
func (c *Client) GetAccount(acct []byte) (*pb.AccountState, error) {
	req := &pb.GetAccountRequest{Account: &pb.AccountId{V: acct}}
	resp := &pb.GetAccountResponse{}
	if err := c.postProto(c.URLs[0]+"/account", req, resp); err != nil {
		return nil, err
	}
	if !resp.Ok || resp.State == nil {
		return nil, fmt.Errorf("account failed: %v", resp.Error)
	}
	return resp.State, nil
}

// Head returns the current head + seq of an account (zero head + 0 seq if absent).
func (c *Client) Head(acct []byte) (head [32]byte, seq uint64, err error) {
	st, err := c.GetAccount(acct)
	if err != nil {
		return head, 0, err
	}
	if st.Head != nil && len(st.Head.V) == 32 {
		copy(head[:], st.Head.V)
	}
	return head, st.Seq, nil
}

// ListReceivables returns unclaimed receivables destined to acct (first URL).
func (c *Client) ListReceivables(acct []byte) ([]*pb.Receivable, error) {
	req := &pb.ListReceivablesRequest{Account: &pb.AccountId{V: acct}, IncludeClaimed: false}
	resp := &pb.ListReceivablesResponse{}
	if err := c.postProto(c.URLs[0]+"/receivables", req, resp); err != nil {
		return nil, err
	}
	if !resp.Ok {
		return nil, fmt.Errorf("receivables failed: %v", resp.Error)
	}
	return resp.Receivables, nil
}

// WaitForReceivable polls until a receivable destined to acct appears (optionally
// matching wantRID), returning its id. Panics on timeout.
func (c *Client) WaitForReceivable(acct []byte, wantRID []byte, pollEvery, maxWait time.Duration) [32]byte {
	deadline := time.Now().Add(maxWait)
	for {
		recs, err := c.ListReceivables(acct)
		if err == nil {
			for _, r := range recs {
				if r == nil || r.Id == nil || len(r.Id.V) != 32 {
					continue
				}
				if wantRID == nil || bytes.Equal(r.Id.V, wantRID) {
					var rid [32]byte
					copy(rid[:], r.Id.V)
					return rid
				}
			}
		}
		if time.Now().After(deadline) {
			panic("timed out waiting for receivable")
		}
		time.Sleep(pollEvery)
	}
}

// WaitForSeqAtLeast polls until acct's seq reaches wantSeq. Panics on timeout.
func (c *Client) WaitForSeqAtLeast(acct []byte, wantSeq uint64, pollEvery, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for {
		st, err := c.GetAccount(acct)
		if err == nil && st.Seq >= wantSeq {
			return
		}
		if time.Now().After(deadline) {
			panic("timed out waiting for seq bump")
		}
		time.Sleep(pollEvery)
	}
}

func (c *Client) postProto(url string, req, resp proto.Message) error {
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(reqBytes))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Accept", "application/x-protobuf")
	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return proto.Unmarshal(body, resp)
}
