package profiles

import (
	"testing"
)

func TestGetProfile(t *testing.T) {
	profile := GetProfile("teams")
	if profile == nil {
		t.Fatal("expected non-nil profile")
	}
	if profile.Name != "Microsoft Teams" {
		t.Errorf("expected Microsoft Teams, got %s", profile.Name)
	}
}

func TestGetProfileDefault(t *testing.T) {
	profile := GetProfile("nonexistent")
	if profile == nil {
		t.Fatal("expected non-nil profile")
	}
	if profile.Name != "Microsoft Teams" {
		t.Error("expected default profile")
	}
}

func TestListProfiles(t *testing.T) {
	profiles := ListProfiles()
	if len(profiles) == 0 {
		t.Error("expected at least one profile")
	}
}

func TestValidateProfile(t *testing.T) {
	profile := &Profile{Name: "test", Protocol: "https"}
	if !ValidateProfile(profile) {
		t.Error("expected valid profile")
	}
}

func TestValidateProfileInvalid(t *testing.T) {
	profile := &Profile{}
	if ValidateProfile(profile) {
		t.Error("expected invalid profile")
	}
}
