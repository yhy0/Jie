package gosqlmap

import (
	_ "embed"
	"fmt"
	"math/rand"
	"strings"
)

func genRandom4Num(source *rand.Rand) string {
	return fmt.Sprintf("%04v", source.Int31n(10000))
}

func genRandomStr(length int, lowercase bool, alphabet string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	result := string(b)
	if lowercase {
		return strings.ToLower(result)
	}
	return result
}

func genHeuristicCheckPayload() string {
	payload := genRandomStr(10, false, HEURISTIC_CHECK_ALPHABET)
	if strings.Count(payload, "\"") != 1 || strings.Count(payload, "'") != 1 {
		payload = genHeuristicCheckPayload()
	}
	return payload
}
