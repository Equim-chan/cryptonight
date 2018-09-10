// +build !amd64

package cryptonight

func (cc *cache) sum(data []byte, variant int) []byte {
	return cc.sumGo(data, variant)
}
