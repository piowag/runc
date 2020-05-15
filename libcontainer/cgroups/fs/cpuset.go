// +build linux

package fs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"
)

type CpusetGroup struct {
}

func (s *CpusetGroup) Name() string {
	return "cpuset"
}

func (s *CpusetGroup) Apply(d *cgroupData) error {
	dir, err := d.path("cpuset")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}
	return s.ApplyDir(dir, d.config, d.pid)
}

func (s *CpusetGroup) Set(path string, cgroup *configs.Cgroup) error {
	if cgroup.Resources.CpusetCpus != "" {
		if err := fscommon.WriteFile(path, "cpuset.cpus", cgroup.Resources.CpusetCpus); err != nil {
			return err
		}
	}
	if cgroup.Resources.CpusetMems != "" {
		if err := fscommon.WriteFile(path, "cpuset.mems", cgroup.Resources.CpusetMems); err != nil {
			return err
		}
	}
	return nil
}

func (s *CpusetGroup) Remove(d *cgroupData) error {
	return removePath(d.path("cpuset"))
}

func getNumericStat(path string, filename string, extracted *[]uint16) error {
	fileContent, err := fscommon.GetCgroupParamString(path, filename)
	if err != nil {
		return err
	}
	if len(fileContent) == 0 {
		return fmt.Errorf("%s found to be empty", filepath.Join(path, filename))
	}

	for _, s := range strings.Split(fileContent, ",") {
		if strings.Contains(s, "-") {
			splitted := strings.Split(s, "-")
			if len(splitted) != 2 {
				return fmt.Errorf("Couldn't parse %s", filepath.Join(path, filename))
			}
			min, err := strconv.ParseUint(splitted[0], 10, 16)
			if err != nil {
				return err
			}
			max, err := strconv.ParseUint(splitted[1], 10, 16)
			if err != nil {
				return err
			}
			if min > max {
				return fmt.Errorf("Couldn't parse %s", filepath.Join(path, filename))
			}
			for i := min; i <= max; i++ {
				*extracted = append(*extracted, uint16(i))
			}
		} else {
			value, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return err
			}
			*extracted = append(*extracted, uint16(value))
		}

	}

	return nil
}

func (s *CpusetGroup) GetStats(path string, stats *cgroups.Stats) error {
	var (
		err  error
		cpus []uint16
		mems []uint16
	)
	err = getNumericStat(path, "cpuset.cpus", &cpus)
	if err != nil {
		return err
	}
	cpuExclusive, err := fscommon.GetCgroupParamUint(path, "cpuset.cpu_exclusive")
	if err != nil {
		return err
	}
	err = getNumericStat(path, "cpuset.mems", &mems)
	if err != nil {
		return err
	}
	memHardwall, err := fscommon.GetCgroupParamUint(path, "cpuset.mem_hardwall")
	if err != nil {
		return err
	}
	memExclusive, err := fscommon.GetCgroupParamUint(path, "cpuset.mem_exclusive")
	if err != nil {
		return err
	}
	memoryMigrate, err := fscommon.GetCgroupParamUint(path, "cpuset.memory_migrate")
	if err != nil {
		return err
	}
	memorySpreadPage, err := fscommon.GetCgroupParamUint(path, "cpuset.memory_spread_page")
	if err != nil {
		return err
	}
	memorySpreadSlab, err := fscommon.GetCgroupParamUint(path, "cpuset.memory_spread_slab")
	if err != nil {
		return err
	}
	memoryPressure, err := fscommon.GetCgroupParamUint(path, "cpuset.memory_pressure")
	if err != nil {
		return err
	}
	schedLoadBalance, err := fscommon.GetCgroupParamUint(path, "cpuset.sched_load_balance")
	if err != nil {
		return err
	}
	schedRelaxDomainLevel, err := fscommon.GetCgroupParamInt(path, "cpuset.sched_relax_domain_level")
	if err != nil {
		return err
	}
	stats.CpusetStats.Cpus = cpus
	stats.CpusetStats.CpuExclusive = cpuExclusive
	stats.CpusetStats.Mems = mems
	stats.CpusetStats.MemExclusive = memExclusive
	stats.CpusetStats.MemHardwall = memHardwall
	stats.CpusetStats.MemoryMigrate = memoryMigrate
	stats.CpusetStats.MemorySpreadPage = memorySpreadPage
	stats.CpusetStats.MemorySpreadSlab = memorySpreadSlab
	stats.CpusetStats.MemoryPressure = memoryPressure
	stats.CpusetStats.SchedLoadBalance = schedLoadBalance
	stats.CpusetStats.SchedRelaxDomainLevel = schedRelaxDomainLevel
	return nil
}

func (s *CpusetGroup) ApplyDir(dir string, cgroup *configs.Cgroup, pid int) error {
	// This might happen if we have no cpuset cgroup mounted.
	// Just do nothing and don't fail.
	if dir == "" {
		return nil
	}
	mountInfo, err := ioutil.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	root := filepath.Dir(cgroups.GetClosestMountpointAncestor(dir, string(mountInfo)))
	// 'ensureParent' start with parent because we don't want to
	// explicitly inherit from parent, it could conflict with
	// 'cpuset.cpu_exclusive'.
	if err := s.ensureParent(filepath.Dir(dir), root); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// We didn't inherit cpuset configs from parent, but we have
	// to ensure cpuset configs are set before moving task into the
	// cgroup.
	// The logic is, if user specified cpuset configs, use these
	// specified configs, otherwise, inherit from parent. This makes
	// cpuset configs work correctly with 'cpuset.cpu_exclusive', and
	// keep backward compatibility.
	if err := s.ensureCpusAndMems(dir, cgroup); err != nil {
		return err
	}

	// because we are not using d.join we need to place the pid into the procs file
	// unlike the other subsystems
	return cgroups.WriteCgroupProc(dir, pid)
}

func (s *CpusetGroup) getSubsystemSettings(parent string) (cpus []byte, mems []byte, err error) {
	if cpus, err = ioutil.ReadFile(filepath.Join(parent, "cpuset.cpus")); err != nil {
		return
	}
	if mems, err = ioutil.ReadFile(filepath.Join(parent, "cpuset.mems")); err != nil {
		return
	}
	return cpus, mems, nil
}

// ensureParent makes sure that the parent directory of current is created
// and populated with the proper cpus and mems files copied from
// it's parent.
func (s *CpusetGroup) ensureParent(current, root string) error {
	parent := filepath.Dir(current)
	if libcontainerUtils.CleanPath(parent) == root {
		return nil
	}
	// Avoid infinite recursion.
	if parent == current {
		return fmt.Errorf("cpuset: cgroup parent path outside cgroup root")
	}
	if err := s.ensureParent(parent, root); err != nil {
		return err
	}
	if err := os.MkdirAll(current, 0755); err != nil {
		return err
	}
	return s.copyIfNeeded(current, parent)
}

// copyIfNeeded copies the cpuset.cpus and cpuset.mems from the parent
// directory to the current directory if the file's contents are 0
func (s *CpusetGroup) copyIfNeeded(current, parent string) error {
	var (
		err                      error
		currentCpus, currentMems []byte
		parentCpus, parentMems   []byte
	)

	if currentCpus, currentMems, err = s.getSubsystemSettings(current); err != nil {
		return err
	}
	if parentCpus, parentMems, err = s.getSubsystemSettings(parent); err != nil {
		return err
	}

	if s.isEmpty(currentCpus) {
		if err := fscommon.WriteFile(current, "cpuset.cpus", string(parentCpus)); err != nil {
			return err
		}
	}
	if s.isEmpty(currentMems) {
		if err := fscommon.WriteFile(current, "cpuset.mems", string(parentMems)); err != nil {
			return err
		}
	}
	return nil
}

func (s *CpusetGroup) isEmpty(b []byte) bool {
	return len(bytes.Trim(b, "\n")) == 0
}

func (s *CpusetGroup) ensureCpusAndMems(path string, cgroup *configs.Cgroup) error {
	if err := s.Set(path, cgroup); err != nil {
		return err
	}
	return s.copyIfNeeded(path, filepath.Dir(path))
}
