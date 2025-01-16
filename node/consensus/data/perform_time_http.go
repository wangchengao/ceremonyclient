package data

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
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
	"github.com/iden3/go-iden3-crypto/poseidon"
	cmap "github.com/orcaman/concurrent-map/v2"
	mt "github.com/txaty/go-merkletree"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/database"
	"source.quilibrium.com/quilibrium/monorepo/node/metrics"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

var GlobalTaskPool = &TaskPool{}

var GlobalResultPool = &ResultPool{
	Output: make([]mt.DataBlock, 1),
}

var GlobalStaticData = &StaticData{
	DeviceMap: cmap.New[*DeviceDataStatic](),
	FrameMap:  make(map[uint64]map[string]FrameMachinesDataMap),
	FrameInfo: make(map[uint64]*FrameInfo),
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

var ackTaskStore = cmap.New[AckTaskCache]()

var FrameCulExceedTime = time.Now()

const expirationDuration = 3000 * time.Millisecond // 过期时间

func StoreAckFlag(ackflag string, cache []*TaskData) {
	ackTaskStore.Set(ackflag, AckTaskCache{
		ackCache:  cache,
		timestamp: time.Now(),
	})
}

func ClearAckFlag() {
	ackTaskStore = cmap.New[AckTaskCache]()
}

//func GetAckFlag(ackflag string) (*AckTaskCache, bool) {
//	if taskCache, ok := ackTaskStore.Get(ackflag); ok {
//		return &taskCache, true
//	}
//	return nil, false
//}

func deleteAckFlag(ackflag string) error {
	_, ok := ackTaskStore.Get(ackflag)
	if !ok {
		return fmt.Errorf("ackflag %s not found", ackflag)
	}

	ackTaskStore.Remove(ackflag)
	return nil
}

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

func (tc *TaskCache) RollbackTasks(tasks []*TaskData) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	// 将回滚任务重新放回缓存
	tc.cache = append(tasks, tc.cache...)
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

func changeTaskCnt(taskCnt int64, macAddr string) int64 {
	remainCulDur := FrameCulExceedTime.Sub(time.Now())
	if remainCulDur.Milliseconds() < 5000 {
		return 0
	}

	deviceInfo, ok := GlobalStaticData.DeviceMap.Get(macAddr)
	if !ok {
		return taskCnt
	}

	// 如果计算时间大雨 40s或者小于5s都理解为一场数据走兜底
	if deviceInfo.CulTimeMillion < 5000 || deviceInfo.CulTimeMillion > 40000 {
		return taskCnt
	}

	expectCulDur := time.Duration(deviceInfo.CulTimeMillion) * time.Millisecond

	// 如果剩余计算时间小于期望计算时间，不分发任务
	if remainCulDur.Milliseconds()-1000 < expectCulDur.Milliseconds() {
		return 0
	}

	//newTaskCnt := taskCnt * int64(float64(remainCulDur.Milliseconds())-2500) / expectCulDur.Milliseconds()
	//return newTaskCnt

	maxTaskCnt := int64(400)
	// 如果剩余计算时间大于2倍期望计算时间，分发任务
	if remainCulDur.Milliseconds()-3500 > 2*expectCulDur.Milliseconds() {
		newTaskCnt := taskCnt * (remainCulDur.Milliseconds() - 3500 - expectCulDur.Milliseconds()) / expectCulDur.Milliseconds()
		if newTaskCnt < taskCnt {
			newTaskCnt = taskCnt
		}

		if newTaskCnt > 2*taskCnt && newTaskCnt > 150 {
			newTaskCnt = 2 * taskCnt
		}

		if newTaskCnt > maxTaskCnt {
			newTaskCnt = maxTaskCnt
		}

		//log.Printf("[changeTaskCnt] mac: %v, remainCulDur: %v, expectCulDur: %v, newTaskCnt: %v,  oldtaskCnt: %v\n", macAddr, remainCulDur, expectCulDur, newTaskCnt, taskCnt)
		return newTaskCnt
	}
	// 剩下的尽量贴近计算
	newTaskCnt := taskCnt * int64(float64(remainCulDur.Milliseconds())-2500) / expectCulDur.Milliseconds()
	if newTaskCnt < taskCnt {
		newTaskCnt = taskCnt
	}
	if newTaskCnt > 2*taskCnt && newTaskCnt > 100 {
		newTaskCnt = 2 * taskCnt
	}
	if newTaskCnt > maxTaskCnt {
		newTaskCnt = maxTaskCnt
	}
	//log.Printf("[changeTaskCnt] mac: %v, remainCulDur: %v, expectCulDur: %v, newTaskCnt: %v,  oldtaskCnt: %v\n", macAddr, remainCulDur, expectCulDur, newTaskCnt, taskCnt)

	return newTaskCnt
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

	macAddr := c.Request.FormValue("mac_addr")

	taskCnt = changeTaskCnt(taskCnt, macAddr)
	if taskCnt == 0 {
		c.JSON(http.StatusOK,
			gin.H{
				"code": -1,
				"data": nil,
			})

		return
	}

	// logic
	givenTaskList := taskL2Cache.GetTasksWithL2Cache(int(taskCnt))

	// 5s后更新设备信息
	go func() {
		getTime := time.Now()
		time.Sleep(5 * time.Second)
		if deviceInfo, ok := GlobalStaticData.DeviceMap.Get(macAddr); ok {
			deviceInfo.LastGetTime = getTime
			deviceInfo.LastTaskCnt = len(givenTaskList)
		}
	}()

	// result
	if givenTaskList != nil {
		getTaskResp := ConvertToGetTaskResp(givenTaskList)

		StoreAckFlag(getTaskResp.Ackflag, givenTaskList)

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

	go func() {
		// for data static
		postDataStatic(&postReqData)
		frameStatic(&postReqData, outputCnt)
	}()

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

func AckPostResult(c *gin.Context, cfg *config.Config) {
	t := time.Now()
	// params
	var ackTaskReq AckTaskReq
	err := c.ShouldBindJSON(&ackTaskReq)
	if err != nil {
		log.Printf("[AckPostResult] json error: %v\n", err)
	}
	if time.Since(t) > time.Second {
		log.Printf("[slow query] AckPostResult wait io read time: %v, ack flag: %+v \n", time.Since(t), ackTaskReq.AckFlag)
	}

	startTime := time.Now()
	defer func() {
		userIP := ""
		userIP, _ = utils.GetClientIPByHeaders(c.Request)
		metrics.NodeRequestCount.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Add(1)
		metrics.NodeRequestDuration.With("node", cfg.NodeId, "source", userIP, "method", c.Request.Method, "url", c.Request.URL.Path).Observe(float64(time.Since(startTime).Microseconds()))
	}()

	deleteAckFlag(ackTaskReq.AckFlag)

	// logic
	code := 0
	if ackTaskReq.FrameNumber != GlobalTaskPool.FrameNumber {
		code = 1001
	}

	// result
	c.JSON(http.StatusOK,
		gin.H{
			"code": code,
		})
}

func frameStatic(postReqData *PostTaskReq, outputCnt int) {
	StaticLock.Lock()
	defer StaticLock.Unlock()

	if postReqData == nil || outputCnt == 0 {
		return
	}

	macAddress := postReqData.MacAddr
	if macAddress == "" {
		macAddress = "AA:BB:CC:DD:EE:FF"
	}

	cores := postReqData.CpuCores
	if cores <= 0 {
		cores = 0
	}

	if frameInfo, ok := GlobalStaticData.FrameMap[GlobalTaskPool.FrameNumber]; ok {
		if accountInfo, ok := frameInfo[postReqData.AccountName]; ok {
			accountInfo.OutputCnt += outputCnt

			if accountInfo.Machines == nil {
				accountInfo.Machines = make(map[string]MachineInfo)
			}

			accountInfo.Machines[macAddress] = MachineInfo{
				Cores: cores,
			}

			GlobalStaticData.FrameMap[GlobalTaskPool.FrameNumber][postReqData.AccountName] = accountInfo
		} else {
			GlobalStaticData.FrameMap[GlobalTaskPool.FrameNumber][postReqData.AccountName] = FrameMachinesDataMap{
				AccountName: postReqData.AccountName,
				OutputCnt:   outputCnt,
				Machines: map[string]MachineInfo{
					macAddress: {Cores: cores},
				},
			}
		}
	} else {
		GlobalStaticData.FrameMap[GlobalTaskPool.FrameNumber] = map[string]FrameMachinesDataMap{
			postReqData.AccountName: {
				AccountName: postReqData.AccountName,
				OutputCnt:   outputCnt,
				Machines: map[string]MachineInfo{
					macAddress: {Cores: cores},
				},
			},
		}
	}
}

func postDataStatic(postReqData *PostTaskReq) {
	StaticLock.Lock()
	defer StaticLock.Unlock()
	if postReqData == nil {
		return
	}
	accountName, MacAddr := postReqData.AccountName, postReqData.MacAddr

	if deviceInfo, ok := GlobalStaticData.DeviceMap.Get(MacAddr); ok {
		deviceInfo.LastSubmitTime = time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02 15:04:05")
		deviceInfo.SubmitCnt += 1
		deviceInfo.SubmitOutputCnt += len(postReqData.ChallengeResults)
		deviceInfo.CoreNum = postReqData.CpuCores
		deviceInfo.IpAddress = postReqData.Ip
		deviceInfo.AccountName = accountName

		if deviceInfo.LastTaskCnt > 0 && deviceInfo.CoreNum > 0 {
			lastTaskCnt := deviceInfo.LastTaskCnt
			if deviceInfo.LastTaskCnt < deviceInfo.CoreNum {
				lastTaskCnt = deviceInfo.CoreNum
			}
			deviceInfo.CulTimeMillion = int64(float64(time.Since(deviceInfo.LastGetTime).Milliseconds()) * float64(deviceInfo.CoreNum) / float64(lastTaskCnt))
		}

	} else {
		GlobalStaticData.DeviceMap.Set(MacAddr, &DeviceDataStatic{
			WorkerName:      postReqData.WorkerName,
			MacAddr:         postReqData.MacAddr,
			LastSubmitTime:  time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02 15:04:05"),
			SubmitCnt:       1,
			SubmitOutputCnt: len(postReqData.ChallengeResults),
			CoreNum:         postReqData.CpuCores,
			IpAddress:       postReqData.Ip,
			AccountName:     accountName,
		})
	}
}

func GetStaticData(c *gin.Context) {
	// lock
	StaticLock.Lock()
	defer StaticLock.Unlock()

	// data handler
	frameInfoList := make([]FrameInfoPrint, 0)
	for frameNumber, frameInfoMap := range GlobalStaticData.FrameMap {
		frameDataPrint := FrameInfoPrint{
			FrameNumber: frameNumber,
			PaddingRate: 0.00,
			FrameInfo:   make([]FrameDataStatic, 0),
		}

		totalOutputs := 0
		for accountName, accountData := range frameInfoMap {

			totalCores := 0
			for _, machineInfo := range accountData.Machines {
				totalCores += machineInfo.Cores
			}

			frameDataStatic := FrameDataStatic{
				AccountName: accountName,
				OutputCnt:   accountData.OutputCnt,
				MachineCnt:  len(accountData.Machines),
				Cores:       totalCores,
			}

			totalOutputs += accountData.OutputCnt
			frameDataPrint.FrameInfo = append(frameDataPrint.FrameInfo, frameDataStatic)
		}
		frameDataPrint.RealOutputCnt = totalOutputs

		frameExtraInfo := GetFrameInfo(frameNumber)

		if frameExtraInfo != nil && totalOutputs > 0 {
			totalOutputs += frameExtraInfo.PadCnt
			frameDataPrint.PaddingRate = float64(frameExtraInfo.PadCnt) / float64(totalOutputs)
			frameDataPrint.CulSec = frameExtraInfo.CulSec
			frameDataPrint.FrameAge = frameExtraInfo.FrameAge
		}
		frameDataPrint.BroadcastCnt = totalOutputs
		frameInfoList = append(frameInfoList, frameDataPrint)
	}
	sort.Slice(frameInfoList, func(i, j int) bool {
		return frameInfoList[i].FrameNumber > frameInfoList[j].FrameNumber
	})

	c.JSON(http.StatusOK,
		gin.H{
			"code": 0,
			"data": map[string]interface{}{
				"account_info": GlobalStaticData.DeviceMap,
				"frame_info":   frameInfoList,
			},
		},
	)
}

func UpdateFrameInfo(frameID uint64, increment int, culSec float64, frameAge float64) {
	if _, exists := GlobalStaticData.FrameInfo[frameID]; !exists {
		GlobalStaticData.FrameInfo[frameID] = &FrameInfo{
			PadCnt:   0,
			CulSec:   culSec,
			FrameAge: frameAge,
		}
	}
	GlobalStaticData.FrameInfo[frameID].PadCnt += increment
}

func GetFrameInfo(frameID uint64) *FrameInfo {
	if frameInfo, exists := GlobalStaticData.FrameInfo[frameID]; exists {
		return frameInfo
	}
	return nil
}

func StartCleanupTicker() {
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		cleanupExpiredTasks(expirationDuration)
	}
}

func cleanupExpiredTasks(timeout time.Duration) {
	flags := ackTaskStore.Keys()
	for _, ackFlag := range flags {
		taskCache, ok := ackTaskStore.Get(ackFlag)
		if !ok {
			continue
		}
		if time.Since(taskCache.timestamp) > timeout {
			if len(taskCache.ackCache) != 0 && taskCache.ackCache[0].ChallengeProofRequest.FrameNumber == GlobalTaskPool.FrameNumber {
				log.Printf("[RollbackTasks] ackflag: %s", ackFlag)
				taskL2Cache.RollbackTasks(taskCache.ackCache)
			}
			ackTaskStore.Remove(ackFlag)
		} else if len(taskCache.ackCache) != 0 && taskCache.ackCache[0].ChallengeProofRequest.FrameNumber != GlobalTaskPool.FrameNumber {
			ackTaskStore.Remove(ackFlag)
		}
	}
}

func StoreFrameDataToDB(ring int, peerId []byte) {
	// lock
	StaticLock.Lock()
	frameData, exists := GlobalStaticData.FrameMap[GlobalTaskPool.FrameNumber]
	if !exists {
		StaticLock.Unlock()
		return
	}
	StaticLock.Unlock()

	addr, _ := poseidon.HashBytes(peerId)

	log.Printf("StoreFrameDataToDB addrBytes : 0x%x", addr)

	var pointerRecords []*database.FrameDataStaticDB
	for accountName, data := range frameData {
		pointerRecords = append(pointerRecords, &database.FrameDataStaticDB{
			AccountName: accountName,
			OutputCnt:   data.OutputCnt,
			FrameNumber: GlobalTaskPool.FrameNumber,
			Ring:        uint64(ring),
			PeerId:      fmt.Sprintf("0x%x", addr),
		})
	}

	database.WriteFrameInfoToMySQL(pointerRecords)

}

func AdjustClusterCore(
	configClusterCore int,
	previousFrameNumber uint64,
) int {

	totalOutputs := 0
	if frameMachinesDataMap, exists := GlobalStaticData.FrameMap[previousFrameNumber]; exists {
		for _, accountData := range frameMachinesDataMap {
			totalOutputs += accountData.OutputCnt
		}
		frameInfo := GetFrameInfo(previousFrameNumber)
		if frameInfo != nil && frameInfo.PadCnt >= 0 {
			paddingRate := float64(frameInfo.PadCnt) / float64(totalOutputs+frameInfo.PadCnt)

			if paddingRate < 0.01 {
				// 应该增加
				return configClusterCore + int(configClusterCore/5)
			} else if paddingRate < 0.12 {
				return configClusterCore // 保持不变
			} else {
				// 应该减少
				return configClusterCore - int(frameInfo.PadCnt/4)
			}
		}
	}

	if totalOutputs >= configClusterCore { // 说明有多余
		return configClusterCore + int(configClusterCore/5)
	}

	return configClusterCore
}
