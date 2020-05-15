// +build linux

package fs

import (
	"reflect"
	"testing"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
)

const (
	cpus                  = "0-2,7,12-14\n"
	cpuExclusive          = "1\n"
	mems                  = "1-4,6,9\n"
	memHardwall           = "0\n"
	memExclusive          = "0\n"
	memoryMigrate         = "1\n"
	memorySpreadPage      = "0\n"
	memorySpeadSlab       = "1\n"
	memoryPressure        = "34377\n"
	schedLoadBalance      = "1\n"
	schedRelaxDomainLevel = "-1\n"
)

func TestCpusetSetCpus(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()

	const (
		cpusBefore = "0"
		cpusAfter  = "1-3"
	)

	helper.writeFileContents(map[string]string{
		"cpuset.cpus": cpusBefore,
	})

	helper.CgroupData.config.Resources.CpusetCpus = cpusAfter
	cpuset := &CpusetGroup{}
	if err := cpuset.Set(helper.CgroupPath, helper.CgroupData.config); err != nil {
		t.Fatal(err)
	}

	value, err := fscommon.GetCgroupParamString(helper.CgroupPath, "cpuset.cpus")
	if err != nil {
		t.Fatalf("Failed to parse cpuset.cpus - %s", err)
	}

	if value != cpusAfter {
		t.Fatal("Got the wrong value, set cpuset.cpus failed.")
	}
}

func TestCpusetSetMems(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()

	const (
		memsBefore = "0"
		memsAfter  = "1"
	)

	helper.writeFileContents(map[string]string{
		"cpuset.mems": memsBefore,
	})

	helper.CgroupData.config.Resources.CpusetMems = memsAfter
	cpuset := &CpusetGroup{}
	if err := cpuset.Set(helper.CgroupPath, helper.CgroupData.config); err != nil {
		t.Fatal(err)
	}

	value, err := fscommon.GetCgroupParamString(helper.CgroupPath, "cpuset.mems")
	if err != nil {
		t.Fatalf("Failed to parse cpuset.mems - %s", err)
	}

	if value != memsAfter {
		t.Fatal("Got the wrong value, set cpuset.mems failed.")
	}
}

func TestCpusetStats(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err != nil {
		t.Fatal(err)
	}
	expectedStats := cgroups.CpusetStats{
		Cpus:                  []uint16{0, 1, 2, 7, 12, 13, 14},
		CpuExclusive:          1,
		Mems:                  []uint16{1, 2, 3, 4, 6, 9},
		MemoryMigrate:         1,
		MemHardwall:           0,
		MemExclusive:          0,
		MemorySpreadPage:      0,
		MemorySpreadSlab:      1,
		MemoryPressure:        34377,
		SchedLoadBalance:      1,
		SchedRelaxDomainLevel: -1}
	if !reflect.DeepEqual(expectedStats, actualStats.CpusetStats) {
		t.Errorf("Expected Cpuset stats usage %#v but found %#v\n",
			expectedStats, actualStats.CpusetStats)
	}

}

func TestCpusetStatsEmptyCpusFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     "",
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsCorruptedCpusFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     "0-3,*4^2",
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsEmptyMemsFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     "",
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsCorruptedMemsFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     "0,1,2-5,g-7",
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoCpusFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoCpuExclusiveFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoMemsFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoMemoryMigrateFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoMemHardwallFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNoMemorySpreadPageFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}
func TestCpusetStatsNoMemorySpreadSlabFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}
func TestCpusetStatsNoMemoryPressureFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.sched_load_balance":       schedLoadBalance,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}

func TestCpusetStatsNosSchedLoadBalanceFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":                     cpus,
		"cpuset.cpu_exclusive":            cpuExclusive,
		"cpuset.mems":                     mems,
		"cpuset.mem_hardwall":             memHardwall,
		"cpuset.mem_exclusive":            memExclusive,
		"cpuset.memory_migrate":           memoryMigrate,
		"cpuset.memory_spread_page":       memorySpreadPage,
		"cpuset.memory_spread_slab":       memorySpeadSlab,
		"cpuset.memory_pressure":          memoryPressure,
		"cpuset.sched_relax_domain_level": schedRelaxDomainLevel,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}
func TestCpusetStatsNoSchedRelaxDomainLevelFile(t *testing.T) {
	helper := NewCgroupTestUtil("cpuset", t)
	defer helper.cleanup()
	helper.writeFileContents(map[string]string{
		"cpuset.cpus":               cpus,
		"cpuset.cpu_exclusive":      cpuExclusive,
		"cpuset.mems":               mems,
		"cpuset.mem_hardwall":       memHardwall,
		"cpuset.mem_exclusive":      memExclusive,
		"cpuset.memory_migrate":     memoryMigrate,
		"cpuset.memory_spread_page": memorySpreadPage,
		"cpuset.memory_spread_slab": memorySpeadSlab,
		"cpuset.memory_pressure":    memoryPressure,
		"cpuset.sched_load_balance": schedLoadBalance,
	})

	cpuset := &CpusetGroup{}
	actualStats := *cgroups.NewStats()
	err := cpuset.GetStats(helper.CgroupPath, &actualStats)
	if err == nil {
		t.Fatal("Expected failure")
	}
}
