package data

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	mt "github.com/txaty/go-merkletree"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/metrics"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

var GlobalTaskPool = &TaskPool{}

var GlobalResultPool = &ResultPool{
	Output: make([]mt.DataBlock, 1),
}

type TaskCache struct {
	cache []*TaskData
	mu    sync.Mutex
}

type AckTaskCache struct {
	ackCache  []*TaskData
	timestamp time.Time // 记录任务分发时间
}

var taskL2Cache = &TaskCache{
	cache: make([]*TaskData, 0),
}

var FrameCulExceedTime = time.Now()

const expirationDuration = 3000 * time.Millisecond // 过期时间

func (tc *TaskCache) GetTasksWithL2Cache(taskCnt int) []*TaskData {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	var tasks []*TaskData

	if len(tc.cache) < taskCnt {
		tasks = tc.cache
		taskCnt -= len(tc.cache)
		t := time.Now()
		tc.cache = PickTaskList()
		if time.Since(t) > time.Second {
			log.Printf("[slow query] PickTaskList time: %v, task len: %+v \n", time.Since(t), len(tc.cache))
		}
	}

	if len(tc.cache) == 0 {
		return nil
	}

	if len(tc.cache) >= taskCnt {
		tasks = tc.cache[:taskCnt]
		tc.cache = tc.cache[taskCnt:]
	} else {
		tasks = append(tasks, tc.cache...)
		tc.cache = nil
	}

	return tasks
}

func (tc *TaskCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cache = nil
}

func PickTaskList() []*TaskData {
	TaskLock.Lock()
	defer TaskLock.Unlock()

	if len(GlobalTaskPool.TaskMap) == 0 {
		return nil
	}

	res := make([]*TaskData, 0, len(GlobalTaskPool.TaskMap))

	for _, each := range GlobalTaskPool.TaskMap {
		res = append(res, each)
	}

	if len(res) > 0 {
		sort.Slice(res, func(i, j int) bool {
			return res[i].TaskID < res[j].TaskID
		})
	}

	return res
}

func ConvertToGetTaskResp(givenTaskList []*TaskData) *GetTaskResp {
	var challenges []*ChallengeProof

	for _, each := range givenTaskList {
		challenges = append(challenges, &ChallengeProof{
			PeerId:      each.ChallengeProofRequest.PeerId,
			Core:        each.ChallengeProofRequest.Core,
			Output:      each.ChallengeProofRequest.Output,
			FrameNumber: each.ChallengeProofRequest.FrameNumber,
			Difficulty:  each.ChallengeProofRequest.Difficulty,
		})
	}

	return &GetTaskResp{
		Challenges: challenges,
		Ackflag:    uuid.New().String(),
	}
}

func MGetTask(c *gin.Context, cfg *config.Config) {
	// params
	taskCntStr := c.Request.FormValue("task_cnt")
	taskCnt, _ := strconv.ParseInt(taskCntStr, 10, 64)
	if taskCnt == 0 {
		taskCnt = 1
	}
	startTime := time.Now()
	defer func() {
		userIP := ""
		userIP, _ = utils.GetClientIPByHeaders(c.Request)
		metrics.NodeRequestCount.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Add(1)
		metrics.NodeRequestDuration.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Observe(float64(time.Since(startTime).Microseconds()))
		metrics.NodeTaskRequestCount.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method).Add(float64(taskCnt))
	}()

	// 1% 概率触发, 来保证一直有算力
	if rand.Intn(100) == 1 {
		c.JSON(http.StatusOK,
			gin.H{
				"code": -1,
				"data": nil,
			})
		return
	}

	// logic
	givenTaskList := taskL2Cache.GetTasksWithL2Cache(int(taskCnt))

	// result
	if givenTaskList != nil {
		getTaskResp := ConvertToGetTaskResp(givenTaskList)

		c.JSON(http.StatusOK,
			gin.H{
				"code": 0,
				"data": getTaskResp,
			})
	} else {
		c.JSON(http.StatusOK,
			gin.H{
				"code": -1,
				"data": nil,
			})
	}

}

func PostResult(c *gin.Context, cfg *config.Config) {
	t := time.Now()

	// params
	var postReqData PostTaskReq
	var reader io.ReadCloser
	var err error

	if c.Request.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(c.Request.Body)
		if err != nil {
			log.Printf("Failed to create gzip reader: %+v \n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gzip reader"})
			return
		}
		defer reader.Close()
	} else {
		reader = c.Request.Body
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		log.Printf("c.Request.Body read err: %+v \n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	err = json.Unmarshal(data, &postReqData)
	if err != nil {
		log.Printf("[PostResult] json error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to Unmarshal request body"})
		return
	}
	startTime := time.Now()
	defer func() {
		userIP := ""
		userIP, _ = utils.GetClientIPByHeaders(c.Request)
		metrics.NodeRequestCount.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Add(1)
		metrics.NodeRequestDuration.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Observe(float64(time.Since(startTime).Microseconds()))
	}()

	// init
	outputCnt := 0
	if time.Since(t) > time.Second {
		log.Printf("[slow query] Submit task wait io read time: %v, task len: %+v， mac: %v \n", time.Since(t), len(postReqData.ChallengeResults), postReqData.MacAddr)
	}
	checkPass := true
	TaskLock.Lock()
	for _, each := range postReqData.ChallengeResults {
		if len(each.Output) == 0 || each.FrameNumber != GlobalTaskPool.FrameNumber {
			checkPass = false
			continue
		}

		outPut := tries.NewProofLeaf(each.Output)
		if outPut == nil {
			log.Printf("[PostResult] outPut nil for Core: %v\n", each.Core)
			continue
		}

		GlobalResultPool.Output[each.Core] = outPut
		// 成功的outPut计数+1
		if _, ok := GlobalTaskPool.TaskMap[each.Core]; ok {
			outputCnt += 1
		}

		delete(GlobalTaskPool.TaskMap, each.Core)
	}

	TaskLock.Unlock()

	if !checkPass {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Output err or FrameNumber err"})
		return
	}
	// result
	c.JSON(http.StatusOK,
		gin.H{
			"code": 0,
		})
}
