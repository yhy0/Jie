package util

import (
	"math/rand"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const letterBytesBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const letterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowletterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyz"

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func init() {
	rand.Seed(time.Now().Unix())
}

// RandFromChoices 从choices里面随机获取
func RandFromChoices(n int, choices string) string {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, r.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = r.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(choices) {
			b[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// RandNumber 随机数字
func RandNumber(n int, m int) int {
	rand.Intn(m)
	return rand.Intn(m-n) + n
}

// RandLetters 随机小写字母
func RandLetters(n int) string {
	return RandFromChoices(n, letterBytes)
}

// RandLetterNumbers 随机大小写字母和数字
func RandLetterNumbers(n int) string {
	return RandFromChoices(n, letterNumberBytes)
}

// RandString 随机大小写字母
func RandString(n int) string {
	return RandFromChoices(n, letterBytesBytes)
}

// RandLowLetterNumber 随机小写字母和数字
func RandLowLetterNumber(n int) string {
	return RandFromChoices(n, lowletterNumberBytes)
}
