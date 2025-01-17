package data

import (
	cmap "github.com/orcaman/concurrent-map/v2"
	"log"
	"sync"
	"time"

	mt "github.com/txaty/go-merkletree"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var TaskLock sync.Mutex
var StaticLock sync.Mutex

// TaskPool define
type TaskPool struct {
	FrameNumber uint64 `json:"frame_number,omitempty"`
	TaskMap     map[uint32]*TaskData
	TaskCnt     int
}

type FrameInfo struct {
	PadCnt   int
	CulSec   float64
	FrameAge float64
}

type StaticData struct {
	// key1: mac value: AccountDataStatic
	DeviceMap cmap.ConcurrentMap[string, *DeviceDataStatic]
	// key1: frame_id key2: account_name
	FrameMap map[uint64]map[string]FrameMachinesDataMap
	// key: frame_id
	FrameInfo map[uint64]*FrameInfo
}

type FrameInfoPrint struct {
	FrameNumber   uint64            `json:"frame_number"`
	PaddingRate   float64           `json:"padding_rate"`
	CulSec        float64           `json:"cul_sec"`
	FrameAge      float64           `json:"frame_age"`
	FrameInfo     []FrameDataStatic `json:"frame_info"`
	RealOutputCnt int               `json:"read_output_cnt"`
	BroadcastCnt  int               `json:"broadcast_cnt"`
}

type MachineInfo struct {
	Cores int
}

type FrameMachinesDataMap struct {
	AccountName string
	OutputCnt   int
	Machines    map[string]MachineInfo
}

type FrameDataStatic struct {
	AccountName string `json:"account_name"`
	OutputCnt   int    `json:"output_cnt"`
	Cores       int    `json:"cores"`
	MachineCnt  int    `json:"machine_cnt"`
}

type DeviceDataStatic struct {
	WorkerName      string    `json:"worker_name,omitempty"`
	MacAddr         string    `json:"mac_addr,omitempty"`
	LastSubmitTime  string    `json:"last_submit_time,omitempty"`
	SubmitCnt       int       `json:"submit_cnt,omitempty"`
	SubmitOutputCnt int       `json:"submit_output_cnt,omitempty"`
	CoreNum         int       `json:"core_num,omitempty"`
	IpAddress       string    `json:"ip_address,omitempty"`
	AccountName     string    `json:"account_name,omitempty"`
	LastGetTime     time.Time `json:"-"`
	LastTaskCnt     int       `json:"last_task_cnt,omitempty"`
	CulTimeMillion  int64     `json:"cul_time_million,omitempty"`
}

type TaskData struct {
	TaskID                int
	ChallengeProofRequest *protobufs.ChallengeProofRequest
}

// ResultPool define
type ResultPool struct {
	Output []mt.DataBlock
}

// GetTaskResp : get
type GetTaskResp struct {
	Challenges []*ChallengeProof `json:"challenges,omitempty"`
	Ackflag    string            `json:"ack_flag,omitempty"`
}

type ChallengeProof struct {
	PeerId      []byte `json:"peer_id,omitempty"`
	Core        uint32 `json:"core,omitempty"`
	Output      []byte `json:"output,omitempty"`
	FrameNumber uint64 `json:"frame_number,omitempty"`
	Difficulty  uint32 `json:"difficulty,omitempty"`
}

type PostTaskReq struct {
	ChallengeResults []*ChallengeProofResult `json:"challenge_results,omitempty"`

	AccountName string `json:"account_name,omitempty"`
	WorkerName  string `json:"worker_name,omitempty"`
	MacAddr     string `json:"mac_addr,omitempty"`
	Ip          string `json:"ip,omitempty"`
	CpuCores    int    `json:"cpu_cores,omitempty"`
}

type AckTaskReq struct {
	FrameNumber uint64 `json:"frame_number,omitempty"`
	AckFlag     string `json:"ack_flag,omitempty"`
}

type ChallengeProofResult struct {
	FrameNumber uint64 `json:"frame_number,omitempty"`
	Core        uint32 `json:"core,omitempty"`
	Output      []byte `json:"output,omitempty"`
}

func (t *TaskPool) PrintFailTaskList() {
	for _, each := range t.TaskMap {
		log.Printf("[PrintFailTaskList] task: %v\n", each.TaskID)
	}
}

func (t *TaskPool) Init(newTasks []*TaskData, frameNumber uint64, clusterCore int) {
	TaskLock.Lock()
	defer TaskLock.Unlock()
	GlobalTaskPool.FrameNumber = frameNumber

	GlobalTaskPool.TaskMap = make(map[uint32]*TaskData, clusterCore)

	for _, each := range newTasks {
		if each == nil || each.ChallengeProofRequest == nil {
			continue
		}
		GlobalTaskPool.TaskMap[each.ChallengeProofRequest.Core] = each
	}

	GlobalTaskPool.TaskCnt = len(newTasks)
	GlobalResultPool.Output = make([]mt.DataBlock, clusterCore)
}

func (t *TaskPool) ClearTaskPool() {
	GlobalTaskPool.TaskMap = make(map[uint32]*TaskData)
	GlobalTaskPool.TaskCnt = 0
	taskL2Cache.Clear()
	ClearAckFlag()
}
