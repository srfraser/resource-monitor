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
	"path/filepath"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// OutputFormatVersion will allow us to filter output files downstream.
const OutputFormatVersion = '1'

// AvailableStats records which statistics are available on this platform, and
// so shouldn't cause an error if they're empty.
type AvailableStats struct {
	CPUPercent bool
	CPUTimes   bool
	Memory     bool
	DiskIO     bool
	NetIO      bool
}

// ProcCPUStat is a more limited version of cpu.TimesStat to save storage space
type ProcCPUStat struct {
	User    float64 `json:"user"`
	System  float64 `json:"system"`
	Idle    float64 `json:"idle"`
	Iowait  float64 `json:"iowait"`
	Steal   float64 `json:"steal"`
	Percent float64 `json:"percent"`
}

// ProcMemoryInfoStat is a more limited version of process.MemoryInfoStat
type ProcMemoryInfoStat struct {
	RSS  uint64 `json:"rss"`  // bytes
	Swap uint64 `json:"swap"` // bytes
}

// MozNetworkIOStat is a more limited version of net.IOCountersStat
type MozNetworkIOStat struct {
	BytesSent   uint64 `json:"bytes_sent"`   // number of bytes sent
	BytesRecv   uint64 `json:"bytes_recv"`   // number of bytes received
	PacketsSent uint64 `json:"packets_sent"` // number of packets sent
	PacketsRecv uint64 `json:"packets_recv"` // number of packets received
}

// ProcDiskIOStat exists to override the json field names of proc.IOCountersStat
type ProcDiskIOStat struct {
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
}

// MozProcessStat combines existing structs into one for a given standalone proc
// CPU is a map so that we can store per-process data.
type MozProcessStat struct {
	Memory ProcMemoryInfoStat `json:"memory"` // all uint64
	CPU    ProcCPUStat        `json:"cpu"`    // all float64
	DiskIO ProcDiskIOStat     `json:"disk"`   // all uint64
}

// MozCollectedStat combines existing structs into one. This is used per sample
// to aggregate all the data collected from the process's generated proc forest
// CPU is a map so that we can store per-process data.
type MozCollectedStat struct {
	Timestamp         int64                     `json:"timestamp"`
	Processes         map[int32]*MozProcessStat `json:"process_stats"`
	AvailableMemory   uint64                    `json:"available_memory"` // bytes
	MemoryUsedPercent float64                   `json:"system_memory_used_percent"`
	ProcessCount      int                       `json:"process_count"`
	ThreadCount       int32                     `json:"thread_count"`
	NetworkIO         MozNetworkIOStat          `json:"network"` // all uint64

}

// FlatMozProcessStat combines existing structs into one.
// CPU is a map so that we can store per-process data.
type FlatMozProcessStat struct {
	Timestamp         int64              `json:"timestamp"`
	Memory            ProcMemoryInfoStat `json:"memory"`           // all uint64
	AvailableMemory   uint64             `json:"available_memory"` // bytes
	CPU               ProcCPUStat        `json:"cpu"`              // all float64
	DiskIO            ProcDiskIOStat     `json:"disk"`             // all uint64
	MemoryUsedPercent float64            `json:"system_memory_used_percent"`
	ProcessCount      int                `json:"process_count"`
	ThreadCount       int32              `json:"thread_count"`
	NetworkIO         MozNetworkIOStat   `json:"network"` // all uint64
}

// StatDiff the provided MozProcessStat to the current one.
func flattenStat(prev, current MozCollectedStat) FlatMozProcessStat {
	// Memory fields are absolute, not a sum, so don't diff those.
	newStat := FlatMozProcessStat{}

	newStat.Timestamp = current.Timestamp
	newStat.MemoryUsedPercent = current.MemoryUsedPercent
	newStat.ProcessCount = current.ProcessCount
	newStat.ThreadCount = current.ThreadCount
	newStat.AvailableMemory = current.AvailableMemory

	// Counters, so diff is required
	newStat.NetworkIO = MozNetworkIOStat{
		current.NetworkIO.BytesRecv - prev.NetworkIO.BytesRecv,
		current.NetworkIO.BytesSent - prev.NetworkIO.BytesSent,
		current.NetworkIO.PacketsRecv - prev.NetworkIO.PacketsRecv,
		current.NetworkIO.PacketsSent - prev.NetworkIO.PacketsSent,
	}

	for pid, currentProcess := range current.Processes {
		// 0-defaults mean we don't worry if we've not seen it before
		prevProcess, ok := prev.Processes[pid]
		if ok != true {
			prevProcess = &MozProcessStat{}
		}

		newStat.Memory.RSS += currentProcess.Memory.RSS
		newStat.Memory.Swap += currentProcess.Memory.Swap

		newStat.CPU.User += currentProcess.CPU.User - prevProcess.CPU.User
		newStat.CPU.System += currentProcess.CPU.System - prevProcess.CPU.System
		newStat.CPU.Idle += currentProcess.CPU.Idle - prevProcess.CPU.Idle
		newStat.CPU.Iowait += currentProcess.CPU.Iowait - prevProcess.CPU.Iowait
		newStat.CPU.Steal += currentProcess.CPU.Steal - prevProcess.CPU.Steal
		newStat.CPU.Percent += currentProcess.CPU.Percent

		newStat.DiskIO.ReadCount += currentProcess.DiskIO.ReadCount - prevProcess.DiskIO.ReadCount
		newStat.DiskIO.WriteCount += currentProcess.DiskIO.WriteCount - prevProcess.DiskIO.WriteCount
		newStat.DiskIO.ReadBytes += currentProcess.DiskIO.ReadBytes - prevProcess.DiskIO.ReadBytes
		newStat.DiskIO.WriteBytes += currentProcess.DiskIO.WriteBytes - prevProcess.DiskIO.WriteBytes
	}

	return newStat
}

// SystemMemoryInfo summarises information about the system memory usage
type SystemMemoryInfo struct {
	TotalMemory uint64 `json:"vmem_total"`
	TotalSwap   uint64 `json:"swap_total"`
}

// SystemInfo summarises information about the instance
type SystemInfo struct {
	MemoryStats      SystemMemoryInfo `json:"memory_stats"`
	CPULogicalCount  int              `json:"cpu_logical_count"`
	CPUPhysicalCount int              `json:"cpu_physical_count"`
}

// SampleSummaryInt helps summarisation of uint64 based fields
type SampleSummaryInt struct {
	Maximum uint64  `json:"maximum"`
	Mean    float64 `json:"mean"`
	Minimum uint64  `json:"minimum"`
}

// SampleSummaryFloat helps summarisation of float64 based fields
type SampleSummaryFloat struct {
	Maximum float64 `json:"maximum"`
	Mean    float64 `json:"mean"`
	Minimum float64 `json:"minimum"`
}

// SampleSummary helps summarisation the more interesting fields.
type SampleSummary struct {
	CPUUser         SampleSummaryFloat `json:"cpu_user"`
	CPUSystem       SampleSummaryFloat `json:"cpu_system"`
	CPUIowait       SampleSummaryFloat `json:"cpu_iowait"`
	CPUPercent      SampleSummaryFloat `json:"cpu_percent"`
	RSS             SampleSummaryInt   `json:"rss"`
	AvailableMemory SampleSummaryInt   `json:"available_memory"`
	MemoryPercent   SampleSummaryFloat `json:"memory_percent"`
}

// StatsOutput controls the output format of the report.
type StatsOutput struct {
	Version    int64                `json:"version"`
	Start      int64                `json:"start"`
	End        int64                `json:"end"`
	Samples    []FlatMozProcessStat `json:"samples"`
	Summary    SampleSummary        `json:"summary"`
	SystemInfo SystemInfo           `json:"system_info"`
}

func findChildProcesses(proc *process.Process) ([]*process.Process, error) {
	children, err := proc.Children()
	if err != nil {
		return nil, err
	}
	results := append(children, proc)
	for _, process := range children {
		descendants, err := findChildProcesses(process)
		if err == nil {
			results = append(results, descendants...)
		}
	}
	return results, nil
}

// findAllProcesses returns the full set of active child processes
// for the given PID, so we can collect stats on all of them.
func findAllProcesses(pid int) ([]*process.Process, error) {
	parent, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}
	results := make([]*process.Process, 0)
	results = append(results, parent)
	children, err := findChildProcesses(parent)
	if err == nil {
		results = append(results, children...)
	}
	return results, nil
}

func collectStatsFor(proc *process.Process, available AvailableStats) (*MozProcessStat, error) {
	// If we check proc still exists, there is still a race, so let's just gather and test
	// the results.
	statistics := new(MozProcessStat)
	// Attempting to collect the CPU percentage as well to better query for the
	// instance usage.
	cpuPercent, err := proc.CPUPercent()
	if err != nil && available.CPUPercent {
		return nil, err
	}

	cpu, err := proc.Times()
	if err != nil {
		if available.CPUTimes {
			return nil, err
		}
	} else {
		// Three significant digits for the cpu times.
		statistics.CPU = ProcCPUStat{
			math.Round(cpu.User*1000) / 1000,
			math.Round(cpu.System*1000) / 1000,
			math.Round(cpu.Idle*1000) / 1000,
			math.Round(cpu.Iowait*1000) / 1000,
			math.Round(cpu.Steal*1000) / 1000,
			// Round the percentage to 2 decimal places.
			math.Round(cpuPercent*100) / 100}
	}

	memory, err := proc.MemoryInfo()
	if err != nil {
		if available.Memory {
			return nil, err
		}
	} else {
		statistics.Memory = ProcMemoryInfoStat{memory.RSS, memory.Swap}
	}

	diskio, err := proc.IOCounters()
	if err != nil {
		if available.DiskIO {
			return nil, err
		}
	} else {
		statistics.DiskIO = ProcDiskIOStat{diskio.ReadCount, diskio.WriteCount, diskio.ReadBytes, diskio.WriteBytes}
	}

	return statistics, nil
}

func checkUnavailableStats(proc *process.Process) AvailableStats {

	available := AvailableStats{}
	_, err := proc.CPUPercent()
	if err != nil {
		fmt.Printf("CPU Percent: %s\n", err)
		available.CPUPercent = false
	} else {
		available.CPUPercent = true
	}

	_, err = proc.Times()
	if err != nil {
		fmt.Printf("CPU Times: %s\n", err)
		available.CPUTimes = false
	} else {
		available.CPUTimes = true
	}

	_, err = proc.MemoryInfo()
	if err != nil {
		fmt.Printf("MemoryInfo: %s\n", err)
		available.Memory = false
	} else {
		available.Memory = true
	}

	_, err = proc.IOCounters()
	if err != nil {
		fmt.Printf("Disk IO: %s\n", err)
		available.DiskIO = false
	} else {
		available.DiskIO = true
	}

	_, err = proc.NetIOCounters(false)
	if err != nil {
		fmt.Printf("Network IO: %s\n", err)
		available.NetIO = false
	} else {
		available.NetIO = true
	}
	return available
}

// Run the psutil collection.
func collector(pid int, fh *os.File, available AvailableStats) error {

	processes, err := findAllProcesses(pid)
	if err != nil {
		fmt.Printf("Unable to find process list, aborting: %v", err)
		return err
	}
	statistics := new(MozCollectedStat)
	statistics.Timestamp = time.Now().Unix()
	statistics.ProcessCount = len(processes)
	statistics.Processes = make(map[int32]*MozProcessStat)

	for _, proc := range processes {
		// TODO Combine these lines
		procstats, err := collectStatsFor(proc, available)
		if err != nil {
			// Process probably ended between findAllProcesses and here.
			continue
		}
		statistics.Processes[proc.Pid] = procstats
		threads, err := proc.NumThreads()
		if err == nil {
			statistics.ThreadCount += threads
		}
	}

	memory, err := mem.VirtualMemory()
	if err != nil {
		fmt.Printf("Unable to collect system memory statistics\n")
		return err
	}
	statistics.AvailableMemory = memory.Available
	// Round the percentage to 2 decimal places.
	statistics.MemoryUsedPercent = math.Round(memory.UsedPercent*100) / 100

	network, err := net.IOCounters(false) // pernic -> false
	if err != nil {
		if available.NetIO {
			fmt.Printf("Unable to collect system network statistics\n")
			return err
		}
	}
	statistics.NetworkIO = MozNetworkIOStat{}
	for _, iface := range network {
		statistics.NetworkIO.BytesSent += iface.BytesSent
		statistics.NetworkIO.BytesRecv += iface.BytesRecv
		statistics.NetworkIO.PacketsSent += iface.PacketsSent
		statistics.NetworkIO.PacketsRecv += iface.PacketsRecv
	}

	jsonData, err := json.Marshal(statistics)
	if err != nil {
		fmt.Printf("Couldn't format data as json: %v", err)
		return err
	}
	_, err = fh.Write(jsonData)
	if err != nil {
		fmt.Printf("Failed writing to output file: %s", err)
	}
	fh.WriteString("\n")
	return nil
}

func getSystemInfo() *SystemInfo {
	info := new(SystemInfo)
	memInfo := new(SystemMemoryInfo)

	memory, err := mem.VirtualMemory()
	if err != nil {
		log.Fatal(err)
	}
	memInfo.TotalMemory = memory.Total

	swap, err := mem.SwapMemory()
	if err != nil {
		log.Fatal(err)
	}
	memInfo.TotalSwap = swap.Total
	info.MemoryStats = *memInfo

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

// Max returns the larger of x or y.
func Max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}

// Min returns the smaller of x or y.
func Min(x, y uint64) uint64 {
	if x > y {
		return y
	}
	return x
}

func iterMean(currentMean, currentValue float64, itemCount int) float64 {
	return currentMean + ((currentValue - currentMean) / float64(itemCount))
}

// find:
// Maximum used RSS
// Minimum available RSS
// Maximum/Average/Minimum number of processes
// Maximum/Aveage/Minimum number of threads
// Max/Avg/Min CPU User
// Max/Avg/Min CPU System
// Max/Avg/Min CPU IOWait
// Max/Avg/Min CPU Percent
func summarise(samples []FlatMozProcessStat) SampleSummary {
	summaries := new(SampleSummary)

	// Prevent the minimum always being zero
	summaries.CPUUser.Minimum = math.MaxFloat64
	summaries.CPUSystem.Minimum = math.MaxFloat64
	summaries.CPUIowait.Minimum = math.MaxFloat64
	summaries.CPUPercent.Minimum = math.MaxFloat64
	summaries.RSS.Minimum = math.MaxUint64
	summaries.AvailableMemory.Minimum = math.MaxUint64
	summaries.MemoryPercent.Minimum = math.MaxFloat64

	for index, entry := range samples {
		summaries.CPUUser.Maximum = math.Max(entry.CPU.User, summaries.CPUUser.Maximum)
		summaries.CPUUser.Minimum = math.Min(entry.CPU.User, summaries.CPUUser.Minimum)
		summaries.CPUUser.Mean = iterMean(summaries.CPUUser.Mean, entry.CPU.User, index+1)

		summaries.CPUSystem.Maximum = math.Max(entry.CPU.System, summaries.CPUSystem.Maximum)
		summaries.CPUSystem.Minimum = math.Min(entry.CPU.System, summaries.CPUSystem.Minimum)
		summaries.CPUSystem.Mean = iterMean(summaries.CPUSystem.Mean, entry.CPU.System, index+1)

		summaries.CPUIowait.Maximum = math.Max(entry.CPU.Iowait, summaries.CPUIowait.Maximum)
		summaries.CPUIowait.Minimum = math.Min(entry.CPU.Iowait, summaries.CPUIowait.Minimum)
		summaries.CPUIowait.Mean = iterMean(summaries.CPUIowait.Mean, entry.CPU.Iowait, index+1)

		summaries.CPUPercent.Maximum = math.Max(entry.CPU.Percent, summaries.CPUPercent.Maximum)
		summaries.CPUPercent.Minimum = math.Min(entry.CPU.Percent, summaries.CPUPercent.Minimum)
		summaries.CPUPercent.Mean = iterMean(summaries.CPUPercent.Mean, entry.CPU.Percent, index+1)

		summaries.RSS.Maximum = Max(entry.Memory.RSS, summaries.RSS.Maximum)
		summaries.RSS.Minimum = Min(entry.Memory.RSS, summaries.RSS.Minimum)
		summaries.RSS.Mean = iterMean(summaries.RSS.Mean, float64(entry.Memory.RSS), index+1)

		summaries.AvailableMemory.Maximum = Max(entry.AvailableMemory, summaries.AvailableMemory.Maximum)
		summaries.AvailableMemory.Minimum = Min(entry.AvailableMemory, summaries.AvailableMemory.Minimum)
		summaries.AvailableMemory.Mean = iterMean(summaries.AvailableMemory.Mean, float64(entry.AvailableMemory), index+1)

		summaries.MemoryPercent.Maximum = math.Max(entry.MemoryUsedPercent, summaries.MemoryPercent.Maximum)
		summaries.MemoryPercent.Minimum = math.Min(entry.MemoryUsedPercent, summaries.MemoryPercent.Minimum)
		summaries.MemoryPercent.Mean = iterMean(summaries.MemoryPercent.Mean, entry.MemoryUsedPercent, index+1)
	}
	return *summaries
}

func processOutput(filename string, outputFilename string) {
	fh, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Unable to read temporary file: %s\n", err)
	}
	defer fh.Close()

	finalStats := new(StatsOutput)
	savedRecord := MozCollectedStat{}
	initialValue := true

	var start int64 = math.MaxInt64
	var end int64

	s := bufio.NewScanner(fh)
	for s.Scan() {
		var v MozCollectedStat

		data := s.Bytes()
		if err := json.Unmarshal(data, &v); err != nil {
			log.Printf("Can't parse json %s\n", data)
		}
		if initialValue {
			savedRecord = v
			initialValue = false
		}
		newSavedRecord := v
		sample := flattenStat(savedRecord, v)
		finalStats.Samples = append(finalStats.Samples, sample)
		savedRecord = newSavedRecord

		if v.Timestamp < start {
			start = v.Timestamp
		}
		if v.Timestamp > end {
			end = v.Timestamp
		}
	}
	if s.Err() != nil {
		log.Printf("Scan error\n")
	}

	finalStats.Start = start
	finalStats.End = end
	finalStats.SystemInfo = *getSystemInfo()
	finalStats.Version = OutputFormatVersion

	finalStats.Summary = summarise(finalStats.Samples)

	jsonData, err := json.MarshalIndent(finalStats, "", "    ")
	if err != nil {
		log.Printf("Marshalling JSON: %s", err)
	}
	err = os.MkdirAll(filepath.Dir(outputFilename), os.ModePerm)
	if err != nil {
		log.Printf("%s\n", err)
	}
	err = ioutil.WriteFile(outputFilename, jsonData, 0644)
	if err != nil {
		log.Printf("%s\n", err)
	}
}

func main() {
	outputFilePtr := flag.String("output", "dummy_output_file", "Newline-separated JSON output file")
	parentProcess := flag.Int("process", 1, "Parent Process ID to monitor")
	collectionInterval := flag.Int("interval", 1.0, "Data collection interval in seconds")
	flag.Parse()

	// flag module doesn't support mandatory arguments, and there's no sensible default for output file.
	requiredArgs := []string{"output", "process"}
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range requiredArgs {
		if !seen[req] {
			fmt.Printf("Required argument -%s missing", req)
			return
		}
	}

	// Log any collection errors once at the start, then ignore them so we don't end up
	// with a spammy log.
	currentPid := os.Getpid()
	myself, err := process.NewProcess(int32(currentPid))
	if err != nil {
		fmt.Printf("%s", err)
		return
	}
	available := checkUnavailableStats(myself)

	// Set up interval
	ticker := time.NewTicker(time.Duration(*collectionInterval) * time.Second)
	done := make(chan bool) // Us telling ticker to stop
	stop := make(chan bool) // Ticker telling us to stop

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		fmt.Printf("Unable to create temporary file: %s", err)
	}
	// Don't defer closing of the file as we want to process it in this scope.
	defer os.Remove(tmpfile.Name())

	go func(stopParent chan bool) {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				err := collector(*parentProcess, tmpfile, available)
				if err != nil {
					stopParent <- true
					return
				}
			}

		}

	}(stop)

	// Carry on until we're told to stop.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	// Block on either a signal or the ticker telling us it had an error.
	select {
	case <-sigs:
		done <- true
		break
	case <-stop:
		break
	}
	ticker.Stop()

	if err := tmpfile.Close(); err != nil {
		log.Printf("Unable to close temporary file: %s", err)
	}
	processOutput(tmpfile.Name(), *outputFilePtr)
}
