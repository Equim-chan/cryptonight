// +build !amd64

package cryptonight

func (cache *Cache) v2Shuffle(offset uint64) {
	cache.v2ShuffleGo(offset)
}
