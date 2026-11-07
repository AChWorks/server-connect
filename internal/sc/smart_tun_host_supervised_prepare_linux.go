//go:build linux

package sc

// These internal entry points compose the installed guard with the existing
// native transaction. They are not a public Connect/adoption API. A caller
// must retain the activation lock from initial parent publication through
// native receipts and ready publication, or leave the parent for Recovery.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"syscall"
)

func newHostRouteSupervisorPlan(admission hostCoreQAAdmission, peer string, plans [2]HostHealthPlan,
	options SmartTUNHealthOptions, roles [2]smartTUNHealthUnitIdentity, boot string, now int64) (hostRouteJournal, error) {
	var empty hostRouteJournal
	n := admission.Native
	if validateHostNativeJournal(n) != nil || n.Native.LinkStage != "planned" ||
		n.Progress.Ingress.Phase != "pending" || n.Progress.Ingress.SysctlStage != "planned" ||
		n.Progress.Ingress.NFTStage != "planned" || n.Progress.Barrier.Stage != "planned" ||
		boot != n.Progress.Ingress.BootID || now <= 0 || n.Progress.Ingress.Deadline > (1<<63-1)/1000 ||
		n.Progress.Ingress.Deadline*1000 <= now || n.Progress.Ingress.Deadline*1000-now > 600000 {
		return empty, Fault("trial_unsupported", "host supervision requires fresh pre-effect native admission")
	}
	policy, err := compileHostCoreAttachConfig(admission.Profile, plans[0].EndpointIP, n.Progress.Ingress.Underlay, n.TunnelInterface)
	if err != nil || !bytes.Equal(policy, admission.Policy) {
		return empty, Fault("activation_journal_conflict", "selected profile or compiled credential changed")
	}
	n.Version, n.Intent = hostRouteJournalVersion, hostRouteSupervisedIntent
	r := hostRouteJournal{hostCoreJournal: hostCoreJournal{hostNativeJournal: n, Core: hostCoreLedger{
		ProfileID: admission.Profile.ID, ConfigSHA256: sha256Hex(policy), PinnedEndpoint: plans[0].EndpointIP, Stage: "planned",
	}}, Route: hostRouteStage{State: "planned"}, Supervision: hostRouteSupervision{
		Generation: 1, State: "initializing", ManagementPeer: peer, Options: options, Roles: roles, Plans: plans,
		HeartbeatMS: now, LeaseDeadlineMS: now + smartTUNHealthLeaseMS, ReconnectStage: "none",
	}}
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		return empty, err
	}
	r.Route.PolicySHA256 = digest
	if err := validateHostRouteJournal(r); err != nil {
		return empty, err
	}
	if !hostRouteCredentialPlanMatches(policy, r) {
		return empty, Fault("activation_journal_conflict", "health endpoint differs from selected credential")
	}
	return r, nil
}

// Arm only exact trusted, initially idle owned executors, before any journal
// or native effect. A no-journal Health result carries no routing authority.
func (m *Manager) prearmHostRouteSupervisor() ([2]smartTUNHealthUnitIdentity, error) {
	var roles [2]smartTUNHealthUnitIdentity
	if err := m.installedHostSupervisor(); err != nil {
		return roles, err
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); err == nil {
			return Fault("activation_journal_conflict", "existing operation blocks prearm")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := hostNativeCoreIdle(); err != nil {
			return err
		}
		if err := trialGuardUnits(false); err != nil {
			return err
		}
		var err error
		roles, err = smartTUNHealthUnits(false, nil)
		return err
	})
	if err != nil {
		return roles, err
	}
	fail := func(err error) ([2]smartTUNHealthUnitIdentity, error) {
		m.disarmUncommittedSmartTUNHealth(roles)
		m.disarmUncommittedSmartTUNGuard()
		return roles, err
	}
	if err := smartTUNTrialSystemctl("start", trialRecoveryUnit); err != nil {
		return fail(err)
	}
	if err := smartTUNTrialSystemctl("enable", "--now", trialRecoveryTimer); err != nil {
		return fail(err)
	}
	if err := trialGuardScheduled(); err != nil {
		return fail(err)
	}
	if err := smartTUNTrialSystemctl("start", smartTUNHealthUnit); err != nil {
		return fail(err)
	}
	if err := smartTUNTrialSystemctl("enable", "--now", smartTUNHealthTimer); err != nil {
		return fail(err)
	}
	if _, err := smartTUNHealthUnits(true, &roles); err != nil {
		return fail(err)
	}
	return roles, nil
}

func (m *Manager) initializeHostRouteSupervisorLocked(store *activationJournalDir, admission hostCoreQAAdmission,
	peer string, plans [2]HostHealthPlan, options SmartTUNHealthOptions, roles [2]smartTUNHealthUnitIdentity) (hostRouteJournal, error) {
	var empty hostRouteJournal
	if err := m.installedHostSupervisor(); err != nil {
		return empty, err
	}
	if store == nil {
		return empty, Fault("guard_unavailable", "supervised parent requires a retained activation lock")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return empty, err
	}
	if _, _, err := store.readJournal(); err == nil {
		return empty, Fault("activation_journal_conflict", "another operation appeared before supervised initialization")
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	if err := trialGuardScheduled(); err != nil {
		return empty, err
	}
	if _, err := smartTUNHealthUnits(true, &roles); err != nil {
		return empty, err
	}
	state, err := m.load()
	if err != nil || state.Desired != "direct" || state.Selected != admission.Profile.ID {
		return empty, Fault("activation_journal_conflict", "selected profile state changed before supervised initialization")
	}
	profile, err := m.profile(state.Selected)
	if err != nil || !reflect.DeepEqual(profile, admission.Profile) {
		return empty, Fault("activation_journal_conflict", "selected profile bytes changed before supervised initialization")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return empty, err
	}
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return empty, err
	}
	r, err := newHostRouteSupervisorPlan(admission, peer, plans, options, roles, boot, now)
	if err != nil {
		return empty, err
	}
	// The pure constructor cannot reserve native state. Reobserve the host,
	// link absence and actual protected management source under this lock.
	if err := hostNativeLinkPreflight(admission.Native); err != nil {
		return empty, err
	}
	if err := hostIngressNamespace(r.Progress.Ingress); err != nil {
		return empty, err
	}
	if err := hostIngressUnderlay(r.Progress.Ingress); err != nil {
		return empty, err
	}
	_, rawDigest, err := hostIngressRawSnapshot()
	if err != nil || rawDigest != r.Progress.Ingress.RawSHA256 {
		return empty, Fault("trial_resource_conflict", "raw policy changed before supervised initialization")
	}
	path, err := observeGeneralHostSSHPath(peer, r.Progress.Ingress.Underlay)
	if err != nil || path.Local.String() != plans[0].IPv4.UnderlaySource || path.Index != r.Native.UnderlayIndex {
		return empty, Fault("confirmation_unavailable", "protected management source changed")
	}
	if err := writeHostRouteJournal(store, r, nil); err != nil {
		return empty, err
	}
	return r, nil
}

func readyHostRouteSupervisorLocked(store *activationJournalDir, r *hostRouteJournal) (string, error) {
	if store == nil || r == nil || !hostRouteSupervised(*r) || r.Supervision.State != "initializing" ||
		r.Route.State != "observed" || r.Core.Stage != "active_observed" {
		return "", Fault("activation_journal_conflict", "fully receipted initializing host operation required")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return "", err
	}
	current, _, err := loadHostRouteJournal(store)
	if err != nil {
		return "", err
	}
	if current != *r {
		return "", Fault("activation_journal_conflict", "supervised parent changed before ready publication")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return "", err
	}
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return "", err
	}
	if boot != r.Progress.Ingress.BootID || now < r.Supervision.HeartbeatMS || now >= r.Supervision.LeaseDeadlineMS ||
		now >= r.Progress.Ingress.Deadline*1000 {
		return "", Fault("trial_recovery_uncertain", "host initialization deadline expired")
	}
	if err := trialGuardScheduled(); err != nil {
		return "", err
	}
	if _, err := smartTUNHealthUnits(true, &r.Supervision.Roles); err != nil {
		return "", err
	}
	if err := verifyHostRouteActivePolicy(*r); err != nil {
		return "", err
	}
	credential, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if err != nil || !hostRouteCredentialPlanMatches(credential, *r) {
		return "", Fault("trial_resource_conflict", "selected host credential changed")
	}
	unit, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil || unit.activeState != "active" || unit.subState != "running" || unit.mainPID == 0 || unit.result != "success" {
		return "", Fault("trial_recovery_uncertain", "selected host Core is not independently active")
	}
	process, err := readManagementProcess(int(unit.mainPID))
	if err != nil {
		return "", err
	}
	path, err := observeGeneralHostSSHPath(r.Supervision.ManagementPeer, r.Progress.Ingress.Underlay)
	if err != nil || path.Local.String() != r.Supervision.Plans[0].IPv4.UnderlaySource || path.Index != r.Native.UnderlayIndex {
		return "", Fault("confirmation_unavailable", "protected host path changed before ready")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", Fault("confirmation_unavailable", "host confirmation nonce unavailable")
	}
	challenge := hex.EncodeToString(nonce)
	now, err = smartTUNUptimeMillis()
	if err != nil {
		return "", err
	}
	if now >= r.Supervision.LeaseDeadlineMS || now >= r.Progress.Ingress.Deadline*1000 {
		return "", Fault("trial_recovery_uncertain", "host initialization expired during final observation")
	}
	next := *r
	next.Supervision.Generation++
	next.Supervision.State = "awaiting_confirmation"
	next.Supervision.ReadyAfterMS, next.Supervision.HeartbeatMS, next.Supervision.LeaseDeadlineMS = now, now, now+smartTUNHealthLeaseMS
	next.Supervision.CorePID, next.Supervision.CoreStartTicks = unit.mainPID, process.StartTicks
	next.Supervision.ChallengeSHA256 = hostRouteChallengeDigest(next, challenge)
	if err := persistHostRouteParent(store, r, next); err != nil {
		return "", err
	}
	return challenge, nil
}
