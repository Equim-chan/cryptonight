// +build !amd64

package cryptonight

func (cc *cache) v2Shuffle(offset uint64) {
	cc.v2ShuffleGo(offset)
}
