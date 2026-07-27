package ecosystem

// InputStage identifies one consumer of repository input.
type InputStage string

const (
	InputStagePackageCandidates InputStage = "package-candidates"
	InputStageDependencyCVE     InputStage = "dependency-cve"
)

// InputCategory is safe to report because it contains no repository path.
type InputCategory string

const (
	InputCategoryManifest      InputCategory = "package-manifest"
	InputCategoryLock          InputCategory = "package-lock"
	InputCategoryDependency    InputCategory = "dependency-input"
	InputCategoryManagerConfig InputCategory = "package-manager-config"
)

// InputFile is one exact, root-relative regular file an adapter may request.
type InputFile struct {
	Path                  string
	Category              InputCategory
	Optional              bool
	ReviewedManagerConfig bool
}

// InputContract is a complete package-scanner allowlist.
type InputContract struct {
	Stage InputStage
	Files []InputFile
}

// InputProvider describes candidate and dependency scan inputs.
type InputProvider interface {
	PackageInput(allowManagerConfig bool) InputContract
	DependencyInput() InputContract
}

// RootInputProvider resolves adapters whose supported input filename depends
// on the exact selected project root. Implementations inspect only
// adapter-owned root metadata and never search parent directories.
type RootInputProvider interface {
	PackageInputForRoot(root string, allowManagerConfig bool) (InputContract, error)
	DependencyInputForRoot(root string) (InputContract, error)
}

// Detector performs bounded root-only project detection.
type Detector interface {
	Detect(root string) (bool, error)
}

// VerificationProvider maps a discovered package script to reviewed argv.
type VerificationProvider interface {
	VerificationCommand(script string) []string
	VerificationScript(command []string) (string, bool)
}

// Constraints contains normalized, allowlisted project metadata.
type Constraints struct {
	Key                     Key
	Runtime                 string
	RuntimeConstraintSource string
	PackageManagerVersion   string
	LockFormat              string
	Platform                string
}

const (
	// RuntimeConstraintSourceDefault means no project runtime constraint was
	// declared and the embedded runtime policy selected the default.
	RuntimeConstraintSourceDefault = "default"
	// RuntimeConstraintSourceProject means allowlisted project metadata
	// declared the runtime constraint.
	RuntimeConstraintSourceProject = "project"
)

// ConstraintDetector parses only adapter-owned root inputs.
type ConstraintDetector interface {
	DetectConstraints(root, platform string) (Constraints, error)
}

// ToolchainCapabilities records acceptance-tested scanner behavior.
type ToolchainCapabilities struct {
	ReadOnlyDiscovery bool
	ReleaseAge        bool
	ProjectConfig     bool
}

// ToolchainSpec is a data-only embedded default. Build arguments are fixed by
// trusted adapter code and are never sourced from project configuration.
type ToolchainSpec struct {
	ID                    string
	Key                   Key
	AdapterVersion        string
	Runtime               string
	PackageManagerVersion string
	Scanner               string
	ScannerVersion        string
	Platform              string
	User                  string
	LockFormats           []string
	Capabilities          ToolchainCapabilities
	Dockerfile            string
	BuildArgs             map[string]string
}

// ToolchainProvider resolves one built-in default without executing it.
type ToolchainProvider interface {
	DefaultToolchain(Constraints) (ToolchainSpec, error)
}

// ProfilePolicy is the immutable validation contract for operator overrides.
type ProfilePolicy struct {
	ExpectedScanner    string
	AllowedLockFormats []string
	VersionOutputStyle string
}

// ProfilePolicyProvider validates public toolchain profile compatibility
// without constructing or executing a default.
type ProfilePolicyProvider interface {
	ProfilePolicy() ProfilePolicy
}

// ScannerRequest contains normalized core policy used to construct reviewed
// scanner argv.
type ScannerRequest struct {
	ProfileScanner    string
	ScannerVersion    string
	InstalledTool     bool
	MinReleaseAgeDays int
}

// ScannerSpec contains only a reviewed argv vector and decoder identity.
type ScannerSpec struct {
	Kind              string
	ExpectedScanner   string
	Args              []string
	Decoder           string
	AcceptedExitCodes []int
	ReleaseAge        bool
	LegacyImageKey    string
	LegacyToolKey     string
}

// ScannerProvider selects candidate scanner argv and its structured decoder.
type ScannerProvider interface {
	Scanner(ScannerRequest) (ScannerSpec, error)
}

// Diagnostic is a bounded, path-safe parser issue that never becomes update
// plan input.
type Diagnostic struct {
	File     string
	Line     int
	Code     string
	Severity string
	Message  string
}

// CandidateReport is normalized scanner output.
type CandidateReport struct {
	Candidates  []Candidate
	Diagnostics []Diagnostic
}

// CandidateDecoder turns untrusted structured output into normalized data.
// inputs contains only files already admitted by the adapter's scan contract.
type CandidateDecoder interface {
	DecodeCandidates(output []byte, inputs map[string][]byte) (CandidateReport, error)
}

// MutationSpec describes the exact files and argv used by the core updater.
// It cannot express a shell, inherited environment, mount, registry, or
// execution boundary.
type MutationSpec struct {
	LockFile       string
	Commands       [][]string
	LegacyImageKey string
	LegacyToolKey  string
}

// MutationRequest contains normalized tool identity selected by core.
type MutationRequest struct {
	Root           string
	ProfileScanner string
	ScannerVersion string
	InstalledTool  bool
}

// MutationProvider is intentionally absent from scan-only adapters.
type MutationProvider interface {
	Mutation(MutationRequest) (MutationSpec, error)
}

// Candidate is the normalized, non-executable adapter view of an update.
type Candidate struct {
	Kind    string
	Name    string
	Current string
	Target  string
	File    string
}

// PlannedMutationRequest binds reviewed snapshot candidates to explicit core
// policy before an adapter constructs argv.
type PlannedMutationRequest struct {
	Root              string
	Candidates        []Candidate
	ProfileScanner    string
	ScannerVersion    string
	InstalledTool     bool
	AllowScripts      bool
	MinReleaseAgeDays int
}

// CandidateMutation describes either exact core-owned manifest rewriting or
// reviewed container argv for one candidate.
type CandidateMutation struct {
	Candidate Candidate
	Rewrite   string
	Commands  [][]string
}

// PlannedMutationSpec is a complete candidate-bound mutation plan. Rewrite
// and Validation are closed core-owned operation identifiers, not executable
// templates.
type PlannedMutationSpec struct {
	LockFile       string
	LegacyImageKey string
	LegacyToolKey  string
	Mutations      []CandidateMutation
	FinalCommands  [][]string
	Validation     string
}

// PlannedMutationProvider is intentionally absent from scan-only adapters.
type PlannedMutationProvider interface {
	PlannedMutation(PlannedMutationRequest) (PlannedMutationSpec, error)
}

// ChangePolicy owns the exact project paths a package mutation may change.
type ChangePolicy interface {
	AllowedChangedPaths() []string
}
