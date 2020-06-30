package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// MozProcessStat combines existing structs into one.
type MozProcessStat struct {
	Timestamp int64                  `json:"timestamp"`
	Memory    process.MemoryInfoStat `json:"memory"`  // all uint64
	CPU       cpu.TimesStat          `json:"cpu"`     // all float64 apart from CPU: string
	DiskIO    process.IOCountersStat `json:"disk"`    // all uint64
	NetworkIO net.IOCountersStat     `json:"network"` // all uint64
}

// Add the provided MozProcessStat to the current one.
func (m *MozProcessStat) Add(data MozProcessStat) {
	// Maybe there's a way of doing this with reflect
	m.Memory.RSS += data.Memory.RSS
	m.Memory.VMS += data.Memory.VMS
	m.Memory.HWM += data.Memory.HWM
	m.Memory.Data += data.Memory.Data
	m.Memory.Stack += data.Memory.Stack
	m.Memory.Locked += data.Memory.Locked
	m.Memory.Swap += data.Memory.Swap

	// Ignore CPU Name string
	m.CPU.User += data.CPU.User
	m.CPU.System += data.CPU.System
	m.CPU.Idle += data.CPU.Idle
	// Ignore CPU Nice, as that doesn't meaningfully sum
	m.CPU.Iowait += data.CPU.Iowait
	m.CPU.Irq += data.CPU.Irq
	m.CPU.Softirq += data.CPU.Softirq
	m.CPU.Steal += data.CPU.Steal
	m.CPU.Guest += data.CPU.Guest
	// Ignore CPU GuestNice, as that doesn't meaningfully sum

	m.DiskIO.ReadCount += data.DiskIO.ReadCount
	m.DiskIO.WriteCount += data.DiskIO.WriteCount
	m.DiskIO.ReadBytes += data.DiskIO.ReadBytes
	m.DiskIO.WriteBytes += data.DiskIO.WriteBytes

	m.NetworkIO.BytesSent += data.NetworkIO.BytesSent
	m.NetworkIO.BytesRecv += data.NetworkIO.BytesRecv
	m.NetworkIO.PacketsSent += data.NetworkIO.PacketsSent
	m.NetworkIO.PacketsRecv += data.NetworkIO.PacketsRecv
	m.NetworkIO.Errin += data.NetworkIO.Errin
	m.NetworkIO.Errout += data.NetworkIO.Errout
	m.NetworkIO.Dropin += data.NetworkIO.Dropin
	m.NetworkIO.Dropout += data.NetworkIO.Dropout
	m.NetworkIO.Fifoin += data.NetworkIO.Fifoin
	m.NetworkIO.Fifoout += data.NetworkIO.Fifoout
}

// Diff the provided MozProcessStat to the current one.
func (m *MozProcessStat) Diff(data MozProcessStat) {
	// Ignore CPU string
	m.CPU.User -= data.CPU.User
	m.CPU.System -= data.CPU.System
	m.CPU.Idle -= data.CPU.Idle
	m.CPU.Iowait -= data.CPU.Iowait
	m.CPU.Irq -= data.CPU.Irq
	m.CPU.Softirq -= data.CPU.Softirq
	m.CPU.Steal -= data.CPU.Steal
	m.CPU.Guest -= data.CPU.Guest

	m.DiskIO.ReadCount -= data.DiskIO.ReadCount
	m.DiskIO.WriteCount -= data.DiskIO.WriteCount
	m.DiskIO.ReadBytes -= data.DiskIO.ReadBytes
	m.DiskIO.WriteBytes -= data.DiskIO.WriteBytes

	m.NetworkIO.BytesSent -= data.NetworkIO.BytesSent
	m.NetworkIO.BytesRecv -= data.NetworkIO.BytesRecv
	m.NetworkIO.PacketsSent -= data.NetworkIO.PacketsSent
	m.NetworkIO.PacketsRecv -= data.NetworkIO.PacketsRecv
	m.NetworkIO.Errin -= data.NetworkIO.Errin
	m.NetworkIO.Errout -= data.NetworkIO.Errout
	m.NetworkIO.Dropin -= data.NetworkIO.Dropin
	m.NetworkIO.Dropout -= data.NetworkIO.Dropout
	m.NetworkIO.Fifoin -= data.NetworkIO.Fifoin
	m.NetworkIO.Fifoout -= data.NetworkIO.Fifoout
}

// SystemMemoryInfo summarises information about the system memory usage
type SystemMemoryInfo struct {
	TotalMemory      uint64  `json:"vmem_total`
	TotalSwap        uint64  `json:"swap_total"`
	AvailableMemory  uint64  `json:"vmem_available`
	UsedPercent      int `json:"vmem_used_percent`
}

// SystemInfo summarises information about the instance
type SystemInfo struct {
	MemoryStats      SystemMemoryInfo `json:"memory_stats"`
	CPULogicalCount  int              `json:"cpu_logical_count"`
	CPUPhysicalCount int              `json:"cpu_physical_count"`
}

// StatsOutput controls the output format of the report.
type StatsOutput struct {
	Start      int64            `json:"start"`
	End        int64            `json:"end"`
	Samples    []MozProcessStat `json:"samples"`
	SystemInfo SystemInfo       `json:"system_info"`
}

func findAllProcesses() ([]*process.Process, error) {
	currentPid := os.Getpid()
	myself, err := process.NewProcess(int32(currentPid))
	if err != nil {
		return nil, err
	}
	parent, err := myself.Parent()
	if err != nil {
		return nil, err
	}
	children, _ := parent.Children()
	return children, nil
}

func collectStatsForWithError(proc *process.Process, withError bool) (*MozProcessStat, error) {

	statistics := new(MozProcessStat)

	cpu, err := proc.Times()
	if err != nil {
		if withError {
			log.Printf("CPU Times: %s\n", err)
		}
	} else {
		statistics.CPU = *cpu
	}

	memory, err := proc.MemoryInfo()
	if err != nil {
		if withError {
			log.Printf("MemoryInfo: %s\n", err)
		}
	} else {
		statistics.Memory = *memory
	}

	diskio, err := proc.IOCounters()
	if err != nil {
		if withError {
			log.Printf("Disk IO: %s\n", err)
		}
	} else {
		statistics.DiskIO = *diskio
	}

	total := new(net.IOCountersStat)
	netio, err := proc.NetIOCounters(false)
	if err != nil {
		if withError {
			log.Printf("Network IO: %s\n", err)
		}
	} else {
		for _, iface := range netio {
			total.BytesSent += iface.BytesSent
			total.BytesRecv += iface.BytesRecv
			total.PacketsSent += iface.PacketsSent
			total.PacketsRecv += iface.PacketsRecv
			total.Errin += iface.Errin
			total.Errout += iface.Errout
			total.Dropin += iface.Dropin
			total.Dropout += iface.Dropout
			total.Fifoin += iface.Fifoin
			total.Fifoout += iface.Fifoout
		}
		statistics.NetworkIO = *total
	}

	return statistics, err
}

func collectStatsFor(proc *process.Process) *MozProcessStat {
	stats, _ := collectStatsForWithError(proc, false)
	return stats
}

// Run the psutil collection.
func collector(fh *os.File) {

	processes, err := findAllProcesses()
	if err != nil {
		fmt.Printf("Unable to find process list, aborting: %v", err)
		return
	}
	statistics := new(MozProcessStat)
	statistics.Timestamp = time.Now().Unix()

	for _, proc := range processes {
		procstats := collectStatsFor(proc)
		statistics.Add(*procstats)
	}

	jsonData, err := json.Marshal(statistics)
	if err != nil {
		fmt.Printf("Couldn't format data as json: %v", err)
		return
	}
	_, err = fh.Write(jsonData)
	if err != nil {
		log.Fatalf("Failed writing to output file: %s", err)
	}
	fh.WriteString("\n")
}

func getSystemInfo() *SystemInfo {
	info := new(SystemInfo)
	mem_info := new(SystemMemoryInfo)

	memory, err := mem.VirtualMemory()
	if err != nil {
		log.Fatal(err)
	}
	mem_info.TotalMemory = memory.Total
	mem_info.AvailableMemory = memory.Available
	mem_info.UsedPercent = int(memory.UsedPercent)

	swap, err := mem.SwapMemory()
	if err != nil {
		log.Fatal(err)
	}
	mem_info.TotalSwap = swap.Total
	info.MemoryStats = *mem_info

	cpuLogCount, err := cpu.Counts(true)
	if err != nil {
		log.Fatal(err)
	}
	info.CPULogicalCount = cpuLogCount

	cpuPhysCount, err := cpu.Counts(false)
	if err != nil {
		log.Fatal(err)
	}
	info.CPUPhysicalCount = cpuPhysCount
	return info
}

func processOutput(filename string, outputFilename string) {

	fh, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Unable to read temporary file: %s", err)
	}
	defer fh.Close()

	finalStats := new(StatsOutput)
	savedRecord := MozProcessStat{}
	initialValue := true

	var start int64 = math.MaxInt64
	var end int64

	s := bufio.NewScanner(fh)
	for s.Scan() {
		var v MozProcessStat
		if err := json.Unmarshal(s.Bytes(), &v); err != nil {
			log.Fatal("Can't parse json")
		}
		if initialValue {
			savedRecord = v
			initialValue = false
		}
		newSavedRecord := v
		v.Diff(savedRecord)
		finalStats.Samples = append(finalStats.Samples, v)
		savedRecord = newSavedRecord

		if v.Timestamp < start {
			start = v.Timestamp
		}
		if v.Timestamp > end {
			end = v.Timestamp
		}
	}
	if s.Err() != nil {
		log.Fatal("Scan error")
	}

	finalStats.Start = start
	finalStats.End = end
	finalStats.SystemInfo = *getSystemInfo()

	jsonData, err := json.MarshalIndent(finalStats, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(outputFilename, jsonData, 0644)

}

func main() {

	outputFilePtr := flag.String("output", "dummy_output_file", "Newline-separated JSON output file")
	collectionInterval := flag.Int("interval", 1.0, "Data collection interval in seconds")
	flag.Parse()

	// flag module doesn't support mandatory arguments, and there's no sensible default for output file.
	requiredArgs := []string{"output"}
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range requiredArgs {
		if !seen[req] {
			log.Fatalf("Required argument -%s missing", req)
		}
	}

	// Log any collection errors once at the start, then ignore them so we don't end up
	// with a spammy log.
	currentPid := os.Getpid()
	myself, err := process.NewProcess(int32(currentPid))
	if err != nil {
		log.Fatalf("%s", err)
	}
	_, err = collectStatsForWithError(myself, true)
	if err != nil {
		log.Printf("Collection will be missing some data: %s", err)
	}

	// Set up interval
	ticker := time.NewTicker(time.Duration(*collectionInterval) * time.Second)
	done := make(chan bool)

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatalf("Unable to create temporary file: %s", err)
	}
	// Don't defer closing of the file as we want to process it in this scope.
	defer os.Remove(tmpfile.Name())

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// TODO replace with temporary file or directory
				collector(tmpfile)
			}

		}

	}()

	// Carry on until we're told to stop.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs
	ticker.Stop()
	done <- true

	if err := tmpfile.Close(); err != nil {
		log.Fatalf("Unable to close temporary file: %s", err)
	}
	processOutput(tmpfile.Name(), *outputFilePtr)

}
