package deploy

// HostResources is the bounded resource view used before starting another
// application slot.
type HostResources struct {
	FreeMemoryMB int
	FreeDiskMB   int
}

// ResourceProbe returns available host resources for the filesystem that
// contains path.
type ResourceProbe func(path string) (HostResources, error)
