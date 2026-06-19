package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !VerifyPassword("correct-horse-battery-staple", hash) {
		t.Error("VerifyPassword rejected the correct password")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Error("VerifyPassword accepted an incorrect password")
	}
}

func TestHashPassword_DifferentSaltsPerCall(t *testing.T) {
	hash1, _ := HashPassword("same-password")
	hash2, _ := HashPassword("same-password")

	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (bcrypt salts each call)")
	}
}
