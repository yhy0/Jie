package gosqlmap

// SimilarStr return the len of longest string both in str1 and str2 and the positions in str1 and str2
func SimilarStr(str1 []rune, str2 []rune) (int, int, int) {
	var sameLen, tmp, pos1, pos2 = 0, 0, 0, 0
	len1, len2 := len(str1), len(str2)
	for p := 0; p < len1; p++ {
		for q := 0; q < len2; q++ {
			tmp = 0
			for p+tmp < len1 && q+tmp < len2 && str1[p+tmp] == str2[q+tmp] {
				tmp++
			}
			if tmp > sameLen {
				sameLen, pos1, pos2 = tmp, p, q
			}
		}
	}
	return sameLen, pos1, pos2
}

// SimilarChar  return the total length of longest string both in str1 and str2
func SimilarChar(str1 []rune, str2 []rune) int {
	maxLen, pos1, pos2 := SimilarStr(str1, str2)
	total := maxLen
	if maxLen != 0 {
		if pos1 > 0 && pos2 > 0 {
			total += SimilarChar(str1[:pos1], str2[:pos2])
		}
		if pos1+maxLen < len(str1) && pos2+maxLen < len(str2) {
			total += SimilarChar(str1[pos1+maxLen:], str2[pos2+maxLen:])
		}
	}
	return total
}

// SimilarText return a int value in [0, 1], which stands for match level
func SimilarText(str1 string, str2 string) float64 {
	txt1, txt2 := []rune(str1), []rune(str2)
	if len(txt1) == 0 || len(txt2) == 0 {
		return 0
	}
	totalLength := float64(SimilarChar(txt1, txt2))
	return totalLength * 2 / float64(len(txt1)+len(txt2))
}

func checkIsSamePage(currentBody, baseBody []byte) bool {
	currentHTML := string(currentBody)
	baseHTML := string(baseBody)
	isSamePage := false
	// 先计算 PageRatio
	ratio := SimilarText(currentHTML, baseHTML)
	if ratio > UPPER_RATIO_BOUND {
		isSamePage = true
	}
	return isSamePage
}
