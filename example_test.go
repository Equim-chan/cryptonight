package cryptonight

import (
	"fmt"
)

func ExampleSum() {
	blob := []byte("Hello, 世界")
	fmt.Printf("%x\n", Sum(blob, 0)) // original

	blob = []byte("variant 1 requires at least 43 bytes of input.")
	fmt.Printf("%x\n", Sum(blob, 1)) // variant 1
	// Output:
	// 0999794e4e20d86e6a81b54495aeb370b6a9ae795fb5af4f778afaf07c0b2e0e
	// 261124c5a6dca5d4aa3667d328a94ead9a819ae714e1f1dc113ceeb14f1ecf99
}
