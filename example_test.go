package cryptonight

import (
	"encoding/hex"
	"fmt"
)

func ExampleSum() {
	blob := []byte("Hello, 世界")
	fmt.Printf("%x\n", Sum(blob, 0)) // original

	blob = []byte("variant 1 requires at least 43 bytes of input.")
	fmt.Printf("%x\n", Sum(blob, 1)) // variant 1

	blob = []byte("Monero is cash for a connected world. It’s fast, private, and secure.")
	fmt.Printf("%x\n", Sum(blob, 2)) // variant 2
	// Output:
	// 0999794e4e20d86e6a81b54495aeb370b6a9ae795fb5af4f778afaf07c0b2e0e
	// 261124c5a6dca5d4aa3667d328a94ead9a819ae714e1f1dc113ceeb14f1ecf99
	// abb61f40468c70234051e4bb5e8b670812473b2a71e02c9633ef94996a621b96
}

func ExampleCheckHash() {
	hash, _ := hex.DecodeString("8e3c1865f22801dc3df0a688da80701e2390e7838e65c142604cc00eafe34000")
	fmt.Println("Hash difficulty greater than 1000:", CheckHash(hash, 1000))
	fmt.Println("Hash difficulty greater than 2000:", CheckHash(hash, 2000))
	// not necessary to use if you only want to compare
	fmt.Println("Hash difficulty precise value:", Difficulty(hash))
	// Output:
	// Hash difficulty greater than 1000: true
	// Hash difficulty greater than 2000: false
	// Hash difficulty precise value: 1009
}
