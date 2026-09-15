package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/angel-platform/angel/pkg/supabase"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	engine := supabase.NewRulesEngine()

	if err := engine.LoadAllRules(); err != nil {
		log.Fatalf("Failed to load rules: %v", err)
	}

	categories := []string{"c2", "exploit", "auth", "network"}
	for _, cat := range categories {
		rules := engine.GetRules(cat)
		fmt.Printf("Category: %s - %d rules\n", cat, len(rules))
		for _, rule := range rules {
			fmt.Printf("  [%d] %s: %s\n", rule.Priority, rule.Name, rule.Pattern)
		}
	}

	fmt.Println("\nRules loaded successfully!")
	os.Exit(0)
}
