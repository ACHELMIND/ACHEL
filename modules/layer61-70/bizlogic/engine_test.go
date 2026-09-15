package bizlogic

import "testing"

func TestPriceManipulation(t *testing.T) {
	config := BizLogicConfig{
		TargetURL: "http://target/api/checkout",
		Items: []CartItem{
			{ID: "1", Name: "Widget", Price: 29.99, Quantity: 2},
			{ID: "2", Name: "Gadget", Price: 49.99, Quantity: 1},
		},
	}
	engine := NewEngine(config)
	result := engine.PriceManipulation()
	if result.Flaw != LogicFlawPriceManip {
		t.Errorf("expected PriceManip, got %d", result.Flaw)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
	if result.OrigPrice <= 0 {
		t.Error("expected positive original price")
	}
}

func TestQuantityNeg(t *testing.T) {
	config := BizLogicConfig{
		TargetURL: "http://target/api/checkout",
		Items: []CartItem{
			{ID: "1", Name: "License", Price: 99.99, Quantity: 1},
		},
	}
	engine := NewEngine(config)
	result := engine.QuantityNeg()
	if result.Flaw != LogicFlawNegativeQty {
		t.Errorf("expected NegativeQty, got %d", result.Flaw)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
}

func TestCouponAbuse(t *testing.T) {
	config := BizLogicConfig{
		TargetURL: "http://target/api/checkout",
		Coupons:   []string{"SAVE20", "ADMIN100"},
		Items: []CartItem{
			{ID: "1", Name: "Item", Price: 100.00, Quantity: 1},
		},
	}
	engine := NewEngine(config)
	result := engine.CouponAbuse()
	if result.Flaw != LogicFlawCouponAbuse {
		t.Errorf("expected CouponAbuse, got %d", result.Flaw)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
}

func TestRaceCheckout(t *testing.T) {
	config := BizLogicConfig{
		TargetURL:  "http://target/api/checkout",
		NumThreads: 20,
		Items: []CartItem{
			{ID: "1", Name: "Limited", Price: 199.99, Quantity: 1},
		},
	}
	engine := NewEngine(config)
	result := engine.RaceCheckout()
	if result.Flaw != LogicFlawRaceCheckout {
		t.Errorf("expected RaceCheckout, got %d", result.Flaw)
	}
}
