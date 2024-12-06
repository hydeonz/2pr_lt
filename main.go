package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Константы
const (
	alphabet       = "abcdefghijklmnopqrstuvwxyz"
	passwordLength = 5
)

func generatePasswords() []string {
	var passwords []string
	password := make([]byte, passwordLength)
	var generate func(pos int)
	generate = func(pos int) {
		if pos == passwordLength {
			passwords = append(passwords, string(password))
			return
		}
		for _, char := range alphabet {
			password[pos] = byte(char)
			generate(pos + 1)
		}
	}
	generate(0)
	return passwords
}

func checkPassword(password, targetMD5, targetSHA256 string) (bool, bool) {
	md5Hash := md5.Sum([]byte(password))
	md5Str := hex.EncodeToString(md5Hash[:])
	md5Match := (md5Str == targetMD5)

	sha256Hash := sha256.Sum256([]byte(password))
	sha256Str := hex.EncodeToString(sha256Hash[:])
	sha256Match := (sha256Str == targetSHA256)

	return md5Match, sha256Match
}

func bruteForceMultiThread(targetMD5, targetSHA256 string, passwords []string, numGoroutines int) {
	start := time.Now()

	var wg sync.WaitGroup
	ch := make(chan string, 1)
	found := false

	chunkSize := len(passwords) / numGoroutines

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(startIdx, endIdx int) {
			defer wg.Done()
			for _, password := range passwords[startIdx:endIdx] {
				if found {
					return
				}
				md5Match, sha256Match := checkPassword(password, targetMD5, targetSHA256)
				if md5Match || sha256Match {
					if !found {
						ch <- password
						found = true
					}
					return
				}
			}
		}(i*chunkSize, (i+1)*chunkSize)
	}

	select {
	case password := <-ch:
		fmt.Printf("Найден пароль: %s (MD5 совпадение: %t, SHA-256 совпадение: %t)\n", password, true, true)
	}

	wg.Wait()

	end := time.Now()
	fmt.Printf("Многопоточный режим завершён за %v\n", end.Sub(start))
}

func main() {
	hashes := []string{
		"1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
		"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
		"74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f",
		"7a68f09bd992671bb3b19a5e70b7827e",
	}

	//var hashes []string
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Введите количество горутин:")
	numGoroutines, _ := reader.ReadString('\n')

	numGoroutines = strings.TrimSpace(numGoroutines)
	formatNumGoroutines, err := strconv.Atoi(numGoroutines)
	if err != nil {
		fmt.Println("Ошибка: введите целое число.")
		return
	}

	fmt.Println("Количество горутин:", formatNumGoroutines)

	fmt.Println("Введите хэш: ")
	//hash, _ := reader.ReadString('\n')
	//hash = strings.TrimSpace(hash)
	//hashes = append(hashes, hash)

	passwords := generatePasswords()
	fmt.Printf("Пароли были сгенерированы, всего: %d\n", len(passwords))

	for _, hash := range hashes {
		fmt.Printf("\nПоиск пароля для хэша %s в многопоточном режиме (горутины: %d):\n", hash, formatNumGoroutines)
		bruteForceMultiThread(hash, hash, passwords, formatNumGoroutines)
	}
}
