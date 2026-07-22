package simulator

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dariofad/river/manifest"
	"github.com/dariofad/river/my_types"
	"github.com/redis/go-redis/v9"
)

var VERBOSE bool
var BENCH bool
var CYCLES uint32

// RemoveMemlock allows the process to allocate the maps declared by the
// manifest-compiled eBPF runtime.
func RemoveMemlock() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func Start(
	plan *manifest.RuntimePlan,
	simulationMode my_types.Service,
	rawTrajectory map[string]interface{},
	errCh chan error,
	resCh chan my_types.OutputTrace,
	pertCh <-chan map[string]interface{},
	statePertCh <-chan []my_types.StateRecord,
	wg *sync.WaitGroup,
) {
	startPlan(plan, simulationMode, rawTrajectory, errCh, resCh, pertCh, statePertCh, wg)
}

func writeToRedis(ctx context.Context, client *redis.Client, key string, records []my_types.ModelRecord) error {
	values := make([]redis.Z, 0, len(records))
	for _, record := range records {
		values = append(values, redis.Z{Score: float64(record.Time), Member: my_types.ModelRecordToCSVString(record)})
	}
	if _, err := client.ZAdd(ctx, key, values...).Result(); err != nil {
		return errors.New("write monitoring records to Redis: " + err.Error())
	}
	return nil
}

func cmdWasSigkilled(err error) bool {
	if err == nil {
		return false
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func simulationRedisKey(model string) string {
	return "simulation:" + strconv.Itoa(0) + ":" + model
}
