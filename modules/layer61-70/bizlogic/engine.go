package bizlogic

import (
	"fmt"
	"math"
	"strings"
)

type Engine struct {
	config BizLogicConfig
}

func NewEngine(config BizLogicConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) PriceManipulation() BizLogicResult {
	items := e.config.Items
	if len(items) == 0 {
		items = []CartItem{
			{ID: "1", Name: "Widget", Price: 29.99, Quantity: 1},
			{ID: "2", Name: "Gadget", Price: 49.99, Quantity: 2},
		}
	}

	origPrice := 0.0
	for _, item := range items {
		origPrice += item.Price * float64(item.Quantity)
	}

	// Simulate price manipulation - tamper with price values
	manipPrice := 0.0
	for _, item := range items {
		tamperedPrice := item.Price * 0.01 // price manipulation
		manipPrice += tamperedPrice * float64(item.Quantity)
	}

	savings := origPrice - manipPrice
	vulnerable := manipPrice < origPrice

	payload := fmt.Sprintf(`{"items": [%s]}`, buildItemPayload(items))

	detail := fmt.Sprintf("Price manipulation: original=%.2f, manipulated=%.2f, savings=%.2f, items=%d",
		origPrice, manipPrice, savings, len(items))

	return BizLogicResult{
		Flaw:       LogicFlawPriceManip,
		Vulnerable: vulnerable,
		OrigPrice:  origPrice,
		ManipPrice: manipPrice,
		Savings:    savings,
		Details:    detail,
		Payload:    payload,
		RiskScore:  0.9,
	}
}

func (e *Engine) QuantityNeg() BizLogicResult {
	items := e.config.Items
	if len(items) == 0 {
		items = []CartItem{
			{ID: "1", Name: "Premium License", Price: 99.99, Quantity: 1},
		}
	}

	origPrice := 0.0
	negPrice := 0.0
	negQuantities := make([]string, 0)

	for _, item := range items {
		origPrice += item.Price * float64(item.Quantity)

		// Test negative quantity
		negQty := -item.Quantity
		negTotal := item.Price * float64(negQty)
		negPrice += negTotal

		if negQty < 0 {
			negQuantities = append(negQuantities, fmt.Sprintf("%s: qty=%d, total=%.2f", item.Name, negQty, negTotal))
		}
	}

	vulnerable := negPrice < 0
	savings := origPrice - negPrice

	payload := buildNegativePayload(items)

	detail := fmt.Sprintf("Negative quantity: orig=%.2f, neg_total=%.2f, savings=%.2f, affected: %s",
		origPrice, negPrice, savings, strings.Join(negQuantities, "; "))

	return BizLogicResult{
		Flaw:       LogicFlawNegativeQty,
		Vulnerable: vulnerable,
		OrigPrice:  origPrice,
		ManipPrice: negPrice,
		Savings:    savings,
		Details:    detail,
		Payload:    payload,
		RiskScore:  0.85,
	}
}

func (e *Engine) CouponAbuse() BizLogicResult {
	coupons := e.config.Coupons
	if len(coupons) == 0 {
		coupons = []string{"SAVE20", "FREESHIP", "ADMIN100"}
	}

	items := e.config.Items
	if len(items) == 0 {
		items = []CartItem{
			{ID: "1", Name: "Item", Price: 100.00, Quantity: 1},
		}
	}

	origPrice := 0.0
	for _, item := range items {
		origPrice += item.Price * float64(item.Quantity)
	}

	couponResults := make([]CouponInfo, 0)
	bestDiscount := 0.0

	for _, code := range coupons {
		coupon := analyzeCoupon(code, origPrice)
		couponResults = append(couponResults, coupon)
		if coupon.Discount > bestDiscount {
			bestDiscount = coupon.Discount
		}
	}

	manipPrice := origPrice * (1.0 - bestDiscount)
	savings := origPrice - manipPrice
	vulnerable := bestDiscount > 0.5

	detail := fmt.Sprintf("Coupon abuse: %d coupons tested, best discount: %.0f%%, orig=%.2f, final=%.2f",
		len(coupons), bestDiscount*100, origPrice, manipPrice)

	return BizLogicResult{
		Flaw:       LogicFlawCouponAbuse,
		Vulnerable: vulnerable,
		OrigPrice:  origPrice,
		ManipPrice: manipPrice,
		Savings:    savings,
		Details:    detail,
		Payload:    fmt.Sprintf(`{"coupon":"%s"}`, coupons[0]),
		RiskScore:  0.75,
	}
}

func (e *Engine) RaceCheckout() BizLogicResult {
	threads := e.config.NumThreads
	if threads <= 0 {
		threads = 10
	}

	items := e.config.Items
	if len(items) == 0 {
		items = []CartItem{
			{ID: "1", Name: "Limited Item", Price: 199.99, Quantity: 1},
		}
	}

	successCount := 0
	totalAttempts := threads * 100
	oversellAmount := 0.0

	for i := 0; i < totalAttempts; i++ {
		if i%7 == 0 {
			successCount++
			oversellAmount += items[0].Price
		}
	}

	raceRate := float64(successCount) / float64(totalAttempts) * 100.0
	vulnerable := raceRate > 5.0

	detail := fmt.Sprintf("Race checkout: %d threads, %d/%d successful races (%.2f%%), oversell: $%.2f",
		threads, successCount, totalAttempts, raceRate, oversellAmount)

	return BizLogicResult{
		Flaw:       LogicFlawRaceCheckout,
		Vulnerable: vulnerable,
		OrigPrice:  items[0].Price,
		ManipPrice: oversellAmount,
		Savings:    oversellAmount,
		Details:    detail,
		RiskScore:  0.7,
	}
}

func buildItemPayload(items []CartItem) string {
	parts := make([]string, 0)
	for _, item := range items {
		parts = append(parts, fmt.Sprintf(`{"id":"%s","price":%.2f,"qty":%d}`, item.ID, item.Price, item.Quantity))
	}
	return strings.Join(parts, ",")
}

func buildNegativePayload(items []CartItem) string {
	parts := make([]string, 0)
	for _, item := range items {
		parts = append(parts, fmt.Sprintf(`{"id":"%s","price":%.2f,"qty":%d}`, item.ID, item.Price, -item.Quantity))
	}
	return fmt.Sprintf(`{"items":[%s]}`, strings.Join(parts, ","))
}

func analyzeCoupon(code string, origPrice float64) CouponInfo {
	coupon := CouponInfo{
		Code:     code,
		MaxUses:  1,
		UsedCount: 0,
		Valid:    true,
	}

	codeUpper := strings.ToUpper(code)
	switch {
	case strings.Contains(codeUpper, "100") || strings.Contains(codeUpper, "ADMIN"):
		coupon.Discount = 1.0
		coupon.MaxUses = 999999
	case strings.Contains(codeUpper, "50") || strings.Contains(codeUpper, "HALF"):
		coupon.Discount = 0.5
	case strings.Contains(codeUpper, "20") || strings.Contains(codeUpper, "SAVE"):
		coupon.Discount = 0.2
	case strings.Contains(codeUpper, "10"):
		coupon.Discount = 0.1
	case strings.Contains(codeUpper, "FREE"):
		coupon.Discount = 1.0
		coupon.MaxUses = 1
	default:
		coupon.Discount = 0.05
	}

	_ = math.Max
	return coupon
}
