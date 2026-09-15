package bizlogic

type LogicFlaw int

const (
	LogicFlawPriceManip LogicFlaw = iota
	LogicFlawNegativeQty
	LogicFlawCouponAbuse
	LogicFlawRaceCheckout
	LogicFlawCartTamper
	LogicFlawIDOR
)

func (l LogicFlaw) String() string {
	return [...]string{
		"PriceManipulation", "NegativeQty", "CouponAbuse",
		"RaceCheckout", "CartTamper", "IDOR",
	}[l]
}

type PaymentFlow struct {
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Items       []CartItem        `json:"items"`
	CouponCode  string            `json:"coupon_code"`
	Total       float64           `json:"total"`
}

type CartItem struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
}

type BizLogicConfig struct {
	TargetURL     string            `json:"target_url"`
	PaymentFlow   PaymentFlow       `json:"payment_flow"`
	Coupons       []string          `json:"coupons"`
	NumThreads    int               `json:"num_threads"`
	Items         []CartItem        `json:"items"`
}

type BizLogicResult struct {
	Flaw         LogicFlaw `json:"flaw"`
	Vulnerable   bool      `json:"vulnerable"`
	OrigPrice    float64   `json:"orig_price"`
	ManipPrice   float64   `json:"manip_price"`
	Savings      float64   `json:"savings"`
	Details      string    `json:"details"`
	Payload      string    `json:"payload"`
	RiskScore    float64   `json:"risk_score"`
}

type CouponInfo struct {
	Code       string  `json:"code"`
	Discount   float64 `json:"discount"`
	MaxUses    int     `json:"max_uses"`
	UsedCount  int     `json:"used_count"`
	Valid      bool    `json:"valid"`
}
