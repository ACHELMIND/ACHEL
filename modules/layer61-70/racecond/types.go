package racecond

type RaceType int

const (
	RaceTypeTOCTOU RaceType = iota
	RaceTypeDoubleFetch
	RaceTypeSymlinkRace
	RaceTypeFileLock
	RaceTypeAtomicity
)

func (r RaceType) String() string {
	return [...]string{
		"TOCTOU", "DoubleFetch", "SymlinkRace", "FileLock", "Atomicity",
	}[r]
}

type TOCTOUVector struct {
	CheckPath  string `json:"check_path"`
	UsePath    string `json:"use_path"`
	TimeGap    int64  `json:"time_gap_ms"`
	Privileged bool   `json:"privileged"`
}

type RaceCondConfig struct {
	TargetURL    string          `json:"target_url"`
	RaceType     RaceType        `json:"race_type"`
	NumThreads  int             `json:"num_threads"`
	Iterations   int             `json:"iterations"`
	TOCTOUVectors []TOCTOUVector `json:"toctou_vectors"`
	FilePath     string          `json:"file_path"`
}

type RaceCondResult struct {
	RaceType      RaceType     `json:"race_type"`
	Vulnerable    bool         `json:"vulnerable"`
	WindowSize    int64        `json:"window_size_ms"`
	SuccessRate   float64      `json:"success_rate"`
	Attempts      int          `json:"attempts"`
	WinCount      int          `json:"win_count"`
	Details       string       `json:"details"`
	Remediation   string       `json:"remediation"`
}

type RaceWindow struct {
	OpenTime   int64  `json:"open_time"`
	CloseTime  int64  `json:"close_time"`
	WindowMs   int64  `json:"window_ms"`
	Trigger    string `json:"trigger"`
}

type FetchPair struct {
	CheckURL string `json:"check_url"`
	UseURL   string `json:"use_url"`
	Method   string `json:"method"`
}
