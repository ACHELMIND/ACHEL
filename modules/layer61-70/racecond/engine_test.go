package racecond

import "testing"

func TestTOCTOUExploit(t *testing.T) {
	config := RaceCondConfig{
		TargetURL:   "http://target/api/upload",
		RaceType:    RaceTypeTOCTOU,
		NumThreads:  10,
		Iterations:  100,
		TOCTOUVectors: []TOCTOUVector{
			{CheckPath: "/etc/passwd", UsePath: "/tmp/link", TimeGap: 10},
		},
	}
	engine := NewEngine(config)
	result := engine.TOCTOUExploit()
	if result.RaceType != RaceTypeTOCTOU {
		t.Errorf("expected TOCTOU race type, got %d", result.RaceType)
	}
	if result.Attempts <= 0 {
		t.Error("expected positive attempt count")
	}
}

func TestDoubleFetch(t *testing.T) {
	config := RaceCondConfig{
		TargetURL:  "http://target/api/price",
		RaceType:   RaceTypeDoubleFetch,
		NumThreads: 20,
		Iterations: 500,
	}
	engine := NewEngine(config)
	result := engine.DoubleFetch()
	if result.RaceType != RaceTypeDoubleFetch {
		t.Errorf("expected DoubleFetch, got %d", result.RaceType)
	}
	if result.Attempts <= 0 {
		t.Error("expected positive attempts")
	}
}

func TestSymlinkRace(t *testing.T) {
	config := RaceCondConfig{
		FilePath:   "/tmp/target_file",
		NumThreads: 16,
	}
	engine := NewEngine(config)
	result := engine.SymlinkRace()
	if result.RaceType != RaceTypeSymlinkRace {
		t.Errorf("expected SymlinkRace, got %d", result.RaceType)
	}
}

func TestTimeWindow(t *testing.T) {
	config := RaceCondConfig{
		NumThreads: 8,
	}
	engine := NewEngine(config)
	result := engine.TimeWindow()
	if result.RaceType != RaceTypeAtomicity {
		t.Errorf("expected Atomicity, got %d", result.RaceType)
	}
}
