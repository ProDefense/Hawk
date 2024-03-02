package main

import (
	"unicode"
)

func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func removeNonPrintableAscii(input string) string {
	var resultBuilder []rune

	for _, char := range input {
		if unicode.IsPrint(char) && char >= 32 && char != 127 {
			resultBuilder = append(resultBuilder, char)
		}
	}

	return string(resultBuilder)
}
