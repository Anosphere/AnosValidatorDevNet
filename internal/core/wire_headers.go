package core

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// P7.2 network-identity wire headers. Every /peer/* and /sync/* request AND response carries the
// sender's network_id + protocol_version so a mismatched (mis-configured or wrong-network) peer is
// rejected up front — a misconfiguration guard (magic-bytes / chainId), NOT a security boundary
// (consensus is sig-authed regardless of transport). The check is BIDIRECTIONAL: the cmd/validator
// mux middleware validates inbound requests and stamps responses; the engine (below) stamps outbound
// requests and validates resync responses.
const (
	HeaderNetworkID       = "X-Anos-Network-Id"
	HeaderProtocolVersion = "X-Anos-Protocol-Version"
)

// setAnosHeaders stamps this node's network identity on an outbound peer/sync request. Applied at
// every /peer/* + /sync/* egress site so the receiving validator can reject a wrong-network caller.
func (e *Engine) setAnosHeaders(req *http.Request) {
	req.Header.Set(HeaderNetworkID, e.cfg.NetworkID)
	req.Header.Set(HeaderProtocolVersion, strconv.Itoa(e.cfg.ProtocolVersion))
}

// checkAnosResponse verifies a peer's RESPONSE carries our network id + protocol version, so a
// wrong-network peer feeding us /sync/* blocks is rejected before we decode them. It is a NO-OP when
// this node has no configured NetworkID (engine-level unit tests that talk to a server without the
// production middleware); the live harness runs the real binary with NetworkID set and exercises it.
func (e *Engine) checkAnosResponse(resp *http.Response) error {
	if strings.TrimSpace(e.cfg.NetworkID) == "" {
		return nil
	}
	return CheckAnosHeaders(resp.Header.Get(HeaderNetworkID), resp.Header.Get(HeaderProtocolVersion), e.cfg.NetworkID, e.cfg.ProtocolVersion)
}

// CheckAnosHeaders compares a peer's advertised (network id, protocol version) against ours; a
// missing or mismatched value is an error. Exported so the cmd/validator server middleware shares
// the exact comparison used by the resync client. Comparison is case-insensitive on the hex id.
func CheckAnosHeaders(gotID, gotVer, wantID string, wantVer int) error {
	gid := strings.ToLower(strings.TrimSpace(gotID))
	if gid == "" {
		return fmt.Errorf("missing %s header", HeaderNetworkID)
	}
	if gid != strings.ToLower(strings.TrimSpace(wantID)) {
		return fmt.Errorf("network_id mismatch: peer %q != ours", gid)
	}
	gv := strings.TrimSpace(gotVer)
	if gv == "" {
		return fmt.Errorf("missing %s header", HeaderProtocolVersion)
	}
	if gv != strconv.Itoa(wantVer) {
		return fmt.Errorf("protocol_version mismatch: peer %q != ours %d", gv, wantVer)
	}
	return nil
}
