package util

import (
	"math/rand"
	"time"
	"unicode"
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

// RandomFromChoices 从choices里面随机获取
func RandomFromChoices(n int, choices string) string {
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

// RandomNumber 随机数字
func RandomNumber(n int, m int) int {
	rand.Intn(m)
	return rand.Intn(m-n) + n
}

// RandomLetters 随机小写字母
func RandomLetters(n int) string {
	return RandomFromChoices(n, letterBytes)
}

// RandomLetterNumbers 随机大小写字母和数字
func RandomLetterNumbers(n int) string {
	return RandomFromChoices(n, letterNumberBytes)
}

// RandomString 随机大小写字母
func RandomString(n int) string {
	return RandomFromChoices(n, letterBytesBytes)
}

// RandomLowLetterNumber 随机小写字母和数字
func RandomLowLetterNumber(n int) string {
	return RandomFromChoices(n, lowletterNumberBytes)
}

func RandomUpper(s string) string {
	r := []rune(s)
	// 随机选择需要修改大小写的位置
	for {
		pos := rand.Intn(len(r))
		if unicode.IsLower(r[pos]) {
			r[pos] = unicode.ToUpper(r[pos])
			break
		} else if unicode.IsUpper(r[pos]) {
			r[pos] = unicode.ToLower(r[pos])
			break
		}
	}

	// 随机修改其余字符的大小写
	for i := 0; i < len(r); i++ {
		if !unicode.IsLetter(r[i]) {
			continue
		}
		if rand.Intn(2) == 0 {
			r[i] = unicode.ToLower(r[i])
		} else {
			r[i] = unicode.ToUpper(r[i])
		}
	}
	return string(r)
}
