//go:build !js && !wasm

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
)

var (
	clusterUrl = flag.String(
		"cluster-url",
		"",
		"链接矿池地址",
	)
	accountName = flag.String(
		"account-name",
		"quil",
		"用户名",
	)
	workerName = flag.String(
		"worker-name",
		"",
		"矿工名",
	)
	macAddr string = "AA:BB:CC:EE:DD"
)

// 任务结果结构体
type GetTaskResp struct {
	Code int      `json:"code"`
	Data TaskData `json:"data"`
}

type TaskData struct {
	Challenges []ChallengeProof `json:"challenges,omitempty"`
	AckFlag    string           `json:"ack_flag,omitempty"`
}

type PostTaskReq struct {
	ChallengeResults []ChallengeProofResult `json:"challenge_results,omitempty"`
	AccountName      string                 `json:"account_name,omitempty"`
	WorkerName       string                 `json:"worker_name,omitempty"`
	MacAddr          string                 `json:"mac_addr,omitempty"`
}

type ChallengeProof struct {
	PeerId      []byte `json:"peer_id,omitempty"`
	Core        uint32 `json:"core,omitempty"`
	Output      []byte `json:"output,omitempty"`
	FrameNumber uint64 `json:"frame_number,omitempty"`
	Difficulty  uint32 `json:"difficulty,omitempty"`
}

type ChallengeProofResult struct {
	FrameNumber uint64 `json:"frame_number,omitempty"`
	Core        uint32 `json:"core,omitempty"`
	Output      []byte `json:"output,omitempty"`
}

func main() {
	flag.Parse()

	if *workerName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "quil-worker"
		}
		*workerName = hostname
	}

	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			mac := iface.HardwareAddr.String()
			if mac != "" {
				macAddr = mac
				break
			}
		}
	}
	if *clusterUrl != "" {
		for {
			// 获取任务
			log.Printf("start to fetch task from: %s", *clusterUrl)
			tasks, _, err := getTasks(*clusterUrl)
			if err != nil {
				log.Printf("failed to fetch task: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			if len(tasks) == 0 {
				log.Println("no task available wait for 2s")
				time.Sleep(2 * time.Second)
				continue
			}

			ids := make([]int, 0, len(tasks))
			for _, task := range tasks {
				ids = append(ids, int(task.Core))
			}
			slices.Sort(ids)
			startTime := time.Now()
			log.Printf("get task count: %d, core ids: %v", len(tasks), ids)

			results := make([]ChallengeProofResult, 0, len(tasks))
			var wg sync.WaitGroup
			resultsCh := make(chan ChallengeProofResult, len(tasks))

			for _, task := range tasks {
				wg.Add(1)
				go func(task ChallengeProof) {
					defer wg.Done()
					output, err := CalculateChallengeProof(task)
					if err != nil {
						log.Printf("failed to calculate challenge proof: %v", err)
						return
					}
					resultsCh <- ChallengeProofResult{
						FrameNumber: task.FrameNumber,
						Core:        task.Core,
						Output:      output,
					}
				}(task)
			}

			wg.Wait()
			close(resultsCh)

			for result := range resultsCh {
				results = append(results, result)
			}

			// 提交任务结果
			log.Printf("submiting result cul time: %v\n", time.Since(startTime).Seconds())

			for i := 0; i < 10; i++ {
				if err := submitResult(*clusterUrl, results); err == nil {
					break
				}
				log.Printf("failed to submit result: %v", err)
			}
		}
	}
}

func getTasks(masterURL string) ([]ChallengeProof, string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	// get cpu cores
	cores := runtime.NumCPU()
	resp, err := client.Get(masterURL + fmt.Sprintf("/task?task_cnt=%d", cores))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	var tasksResp GetTaskResp
	if err := json.Unmarshal(body, &tasksResp); err != nil {
		return nil, "", err
	}
	return tasksResp.Data.Challenges, tasksResp.Data.AckFlag, nil
}

func CalculateChallengeProof(data ChallengeProof) ([]byte, error) {
	challenge := []byte{}
	challenge = append(challenge, data.PeerId...)

	difficulty := data.Difficulty
	frameNumber := data.FrameNumber
	challenge = binary.BigEndian.AppendUint64(
		challenge,
		frameNumber,
	)
	challenge = binary.BigEndian.AppendUint32(challenge, data.Core)
	challenge = append(challenge, data.Output...)

	if difficulty == 0 || frameNumber == 0 {
		return nil, errors.Wrap(
			errors.New("invalid request"),
			"calculate challenge proof",
		)
	}

	b := sha3.Sum256(challenge)
	o := vdf.WesolowskiSolve(b, uint32(difficulty))

	output := make([]byte, 516)
	copy(output[:], o[:])

	return output, nil
}

func submitResult(masterURL string, result []ChallengeProofResult) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	submitReq := PostTaskReq{
		ChallengeResults: result,
		AccountName:      *accountName,
		WorkerName:       *workerName,
		MacAddr:          macAddr,
	}

	data, err := json.Marshal(submitReq)
	if err != nil {
		return err
	}

	resp, err := client.Post(masterURL+"/task", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("post task result submit response: %s\n", body)
	return nil
}
