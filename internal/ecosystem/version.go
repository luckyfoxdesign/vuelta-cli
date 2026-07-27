package ecosystem

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// RuntimeConstraintInvalid identifies malformed runtime constraint input.
	RuntimeConstraintInvalid = "constraint_invalid"
	// RuntimeConstraintUnsupportedSyntax identifies valid ecosystem syntax
	// outside Vuelta's deliberately bounded conjunction grammar.
	RuntimeConstraintUnsupportedSyntax = "constraint_unsupported_syntax"
	// RuntimeConstraintNoCompatible identifies a valid constraint that does not
	// intersect any supported runtime profile.
	RuntimeConstraintNoCompatible = "no_compatible_runtime"

	maxRuntimeConstraintLength = 256
	maxRuntimeConstraintTerms  = 16
	maxVersionComponent        = 1_000_000
)

var (
	runtimeConstraintTermPattern = regexp.MustCompile(`^(>=|<=|!=|==|~=|>|<|\^|~|=)?(v?[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2})$`)
	operatorWhitespacePattern    = regexp.MustCompile(`(>=|<=|!=|==|~=|>|<|\^|~|=)\s+`)
	hyphenRangePattern           = regexp.MustCompile(`[0-9xX*]\s+-\s+[v0-9]`)
	prereleasePattern            = regexp.MustCompile(`[0-9]-[A-Za-z0-9]`)
)

// RuntimeConstraintError is a stable, typed runtime resolution failure.
type RuntimeConstraintError struct {
	ReasonCode string
	Stack      string
	Constraint string
	Supported  []string
	Detail     string
}

// Error returns a bounded diagnostic safe for structured scan output.
func (e *RuntimeConstraintError) Error() string {
	switch e.ReasonCode {
	case RuntimeConstraintInvalid:
		return fmt.Sprintf("runtime constraint %q is invalid for %s: %s", e.Constraint, e.Stack, e.Detail)
	case RuntimeConstraintUnsupportedSyntax:
		return fmt.Sprintf("runtime constraint %q uses unsupported %s syntax: %s", e.Constraint, e.Stack, e.Detail)
	case RuntimeConstraintNoCompatible:
		return fmt.Sprintf(
			"runtime constraint %q has no compatible embedded %s runtime; supported runtimes are %s",
			e.Constraint, e.Stack, strings.Join(e.Supported, ", "),
		)
	default:
		return fmt.Sprintf("runtime constraint %q cannot be resolved for %s", e.Constraint, e.Stack)
	}
}

// Hint returns the operator action associated with a typed failure.
func (e *RuntimeConstraintError) Hint() string {
	switch e.ReasonCode {
	case RuntimeConstraintInvalid:
		return "Fix the project runtime constraint, or select a compatible digest-pinned update.toolchain_profiles override"
	case RuntimeConstraintUnsupportedSyntax:
		return "Use an exact version, wildcard, caret, tilde, or comparator conjunction; otherwise select a compatible digest-pinned update.toolchain_profiles override"
	case RuntimeConstraintNoCompatible:
		return "Relax the project runtime constraint, or add and select a compatible digest-pinned update.toolchain_profiles override"
	default:
		return "Review the project runtime constraint and configured toolchain profiles"
	}
}

type semanticVersion struct {
	major int
	minor int
	patch int
}

func (v semanticVersion) compare(other semanticVersion) int {
	switch {
	case v.major != other.major:
		return compareInt(v.major, other.major)
	case v.minor != other.minor:
		return compareInt(v.minor, other.minor)
	default:
		return compareInt(v.patch, other.patch)
	}
}

func (v semanticVersion) nextPatch() semanticVersion {
	return semanticVersion{major: v.major, minor: v.minor, patch: v.patch + 1}
}

func (v semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

type versionRange struct {
	lower semanticVersion
	upper *semanticVersion
}

func (r versionRange) intersects(other versionRange) (semanticVersion, *semanticVersion, bool) {
	lower := r.lower
	if other.lower.compare(lower) > 0 {
		lower = other.lower
	}
	upper := minimumUpper(r.upper, other.upper)
	return lower, upper, upper == nil || lower.compare(*upper) < 0
}

type parsedVersion struct {
	value     semanticVersion
	precision int
	wildcard  bool
}

// RuntimeConstraint is a parsed conjunction over stable numeric releases.
// Profiles represent a major (Node), major/minor (Python), or exact runtime
// line, so compatibility means the two bounded version sets intersect.
type RuntimeConstraint struct {
	stack      string
	raw        string
	canonical  string
	lower      semanticVersion
	upper      *semanticVersion
	exclusions []versionRange
}

// Canonical returns the normalized comparator conjunction reported by scans.
func (c RuntimeConstraint) Canonical() string { return c.canonical }

// MatchesProfile reports whether a supported runtime profile intersects the
// parsed project constraint.
func (c RuntimeConstraint) MatchesProfile(profile string) bool {
	if c.raw == "" {
		return true
	}
	candidate, ok := parseProfileRange(profile)
	if !ok {
		return false
	}
	lower, upper, ok := (versionRange{lower: c.lower, upper: c.upper}).intersects(candidate)
	if !ok {
		return false
	}
	return !rangesCover(versionRange{lower: lower, upper: upper}, c.exclusions)
}

// ParseRuntimeConstraint accepts a bounded conjunction grammar shared by Node
// semver, Python requires-python, and Poetry runtime constraints.
func ParseRuntimeConstraint(stack, constraint string) (RuntimeConstraint, error) {
	raw := strings.TrimSpace(constraint)
	parsed := RuntimeConstraint{stack: stack, raw: raw}
	if raw == "" {
		return parsed, nil
	}
	if stack != "node" && stack != "python" {
		return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, "unknown runtime family")
	}
	if len(raw) > maxRuntimeConstraintLength {
		return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw[:maxRuntimeConstraintLength], "value is too long")
	}
	if detail := unsupportedRuntimeSyntax(raw); detail != "" {
		return RuntimeConstraint{}, constraintError(RuntimeConstraintUnsupportedSyntax, stack, raw, detail)
	}
	for _, group := range strings.Split(raw, ",") {
		if strings.TrimSpace(group) == "" {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, "empty comparator")
		}
	}
	normalized := operatorWhitespacePattern.ReplaceAllString(raw, "$1")
	terms := strings.Fields(strings.ReplaceAll(normalized, ",", " "))
	if len(terms) == 0 || len(terms) > maxRuntimeConstraintTerms {
		return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, "constraint has an invalid number of comparators")
	}

	var canonical []string
	for _, term := range terms {
		match := runtimeConstraintTermPattern.FindStringSubmatch(term)
		if match == nil {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, "expected a numeric version comparator")
		}
		operator, literal := match[1], match[2]
		version, err := parseConstraintVersion(stack, literal)
		if err != nil {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, err.Error())
		}
		if operator == "~=" && stack != "python" {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintUnsupportedSyntax, stack, raw, "~= is supported only for Python constraints")
		}
		if operator == "~=" && (version.precision < 2 || version.wildcard) {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintInvalid, stack, raw, "~= requires at least major and minor numeric components")
		}
		var termCanonical []string
		parsed, termCanonical, err = applyConstraintTerm(parsed, operator, version)
		if err != nil {
			return RuntimeConstraint{}, constraintError(RuntimeConstraintUnsupportedSyntax, stack, raw, err.Error())
		}
		canonical = append(canonical, termCanonical...)
	}
	parsed.canonical = strings.Join(canonical, " ")
	return parsed, nil
}

// ResolveRuntime selects the highest compatible supported runtime without
// executing project code. Empty constraints retain the explicit fallback.
func ResolveRuntime(stack, constraint, fallback string, supported []string) (string, error) {
	parsed, err := ParseRuntimeConstraint(stack, constraint)
	if err != nil {
		return "", err
	}
	candidates, err := sortedRuntimeProfiles(supported)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(constraint) == "" {
		for _, candidate := range candidates {
			if candidate.value == fallback {
				return fallback, nil
			}
		}
		return "", fmt.Errorf("fallback %s runtime %q is not in the embedded supported set", stack, fallback)
	}
	for _, candidate := range candidates {
		if parsed.MatchesProfile(candidate.value) {
			return candidate.value, nil
		}
	}
	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, candidate.value)
	}
	return "", &RuntimeConstraintError{
		ReasonCode: RuntimeConstraintNoCompatible,
		Stack:      stack,
		Constraint: parsed.Canonical(),
		Supported:  values,
	}
}

func unsupportedRuntimeSyntax(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(raw, "||") || strings.Contains(lower, " or ") || strings.Contains(raw, "|"):
		return "union constraints are not accepted"
	case strings.Contains(raw, "&&"):
		return "use commas or whitespace for conjunctions"
	case strings.ContainsAny(raw, "()[]{};"):
		return "grouping and set expressions are not accepted"
	case hyphenRangePattern.MatchString(raw):
		return "hyphen ranges are not accepted; use explicit comparators"
	case strings.Contains(raw, "==="):
		return "this operator is outside the bounded grammar"
	case strings.ContainsAny(raw, "+"):
		return "pre-release and build metadata are not accepted"
	case prereleasePattern.MatchString(raw):
		return "pre-release and build metadata are not accepted"
	default:
		return ""
	}
}

func parseConstraintVersion(stack, literal string) (parsedVersion, error) {
	if strings.HasPrefix(literal, "v") {
		if stack != "node" {
			return parsedVersion{}, errorsf("leading v is supported only for Node constraints")
		}
		literal = strings.TrimPrefix(literal, "v")
	}
	parts := strings.Split(literal, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return parsedVersion{}, errorsf("version must contain one to three numeric components")
	}
	result := parsedVersion{precision: len(parts)}
	values := []*int{&result.value.major, &result.value.minor, &result.value.patch}
	for index, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			if index == 0 {
				return parsedVersion{}, errorsf("wildcard must follow a numeric major version")
			}
			result.precision = index
			result.wildcard = true
			for _, remaining := range parts[index+1:] {
				if remaining != "x" && remaining != "X" && remaining != "*" {
					return parsedVersion{}, errorsf("numeric components cannot follow a wildcard")
				}
			}
			break
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > maxVersionComponent {
			return parsedVersion{}, errorsf("version component %q is invalid", part)
		}
		*values[index] = value
	}
	return result, nil
}

func applyConstraintTerm(
	constraint RuntimeConstraint,
	operator string,
	version parsedVersion,
) (RuntimeConstraint, []string, error) {
	if version.wildcard && operator != "" && operator != "=" && operator != "==" && operator != "!=" {
		return RuntimeConstraint{}, nil, errorsf("wildcards require equality or exclusion")
	}
	switch operator {
	case "", "=", "==":
		scope := versionScope(version)
		constraint = intersectConstraint(constraint, scope)
		return constraint, rangeCanonical(scope), nil
	case "!=":
		scope := versionScope(version)
		constraint.exclusions = append(constraint.exclusions, scope)
		return constraint, []string{"!=" + displayScope(version)}, nil
	case ">=":
		constraint = intersectConstraint(constraint, versionRange{lower: version.value})
		return constraint, []string{">=" + version.value.String()}, nil
	case ">":
		lower := version.value.nextPatch()
		constraint = intersectConstraint(constraint, versionRange{lower: lower})
		return constraint, []string{">" + version.value.String()}, nil
	case "<":
		upper := version.value
		constraint = intersectConstraint(constraint, versionRange{upper: &upper})
		return constraint, []string{"<" + version.value.String()}, nil
	case "<=":
		upper := version.value.nextPatch()
		constraint = intersectConstraint(constraint, versionRange{upper: &upper})
		return constraint, []string{"<=" + version.value.String()}, nil
	case "^":
		scope := caretScope(version)
		constraint = intersectConstraint(constraint, scope)
		return constraint, rangeCanonical(scope), nil
	case "~":
		scope := tildeScope(version)
		constraint = intersectConstraint(constraint, scope)
		return constraint, rangeCanonical(scope), nil
	case "~=":
		scope := compatibleReleaseScope(version)
		constraint = intersectConstraint(constraint, scope)
		return constraint, rangeCanonical(scope), nil
	default:
		return RuntimeConstraint{}, nil, errorsf("operator %q is not supported", operator)
	}
}

func versionScope(version parsedVersion) versionRange {
	if version.precision == 3 && !version.wildcard {
		upper := version.value.nextPatch()
		return versionRange{lower: version.value, upper: &upper}
	}
	upper := nextPrefix(version.value, version.precision)
	return versionRange{lower: version.value, upper: &upper}
}

func caretScope(version parsedVersion) versionRange {
	upper := semanticVersion{}
	switch {
	case version.precision == 1:
		upper.major = version.value.major + 1
	case version.value.major > 0:
		upper.major = version.value.major + 1
	case version.precision == 2:
		upper.minor = version.value.minor + 1
	case version.value.minor > 0:
		upper.minor = version.value.minor + 1
	default:
		upper.patch = version.value.patch + 1
	}
	return versionRange{lower: version.value, upper: &upper}
}

func tildeScope(version parsedVersion) versionRange {
	precision := version.precision
	if precision > 2 {
		precision = 2
	}
	upper := nextPrefix(version.value, precision)
	return versionRange{lower: version.value, upper: &upper}
}

func compatibleReleaseScope(version parsedVersion) versionRange {
	precision := 1
	if version.precision == 3 {
		precision = 2
	}
	upper := nextPrefix(version.value, precision)
	return versionRange{lower: version.value, upper: &upper}
}

func nextPrefix(version semanticVersion, precision int) semanticVersion {
	switch precision {
	case 1:
		return semanticVersion{major: version.major + 1}
	case 2:
		return semanticVersion{major: version.major, minor: version.minor + 1}
	default:
		return version.nextPatch()
	}
}

func intersectConstraint(constraint RuntimeConstraint, term versionRange) RuntimeConstraint {
	if term.lower.compare(constraint.lower) > 0 {
		constraint.lower = term.lower
	}
	constraint.upper = minimumUpper(constraint.upper, term.upper)
	return constraint
}

func minimumUpper(left, right *semanticVersion) *semanticVersion {
	switch {
	case left == nil:
		return cloneVersion(right)
	case right == nil:
		return cloneVersion(left)
	case left.compare(*right) <= 0:
		return cloneVersion(left)
	default:
		return cloneVersion(right)
	}
}

func cloneVersion(value *semanticVersion) *semanticVersion {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func rangesCover(target versionRange, exclusions []versionRange) bool {
	if len(exclusions) == 0 {
		return false
	}
	relevant := make([]versionRange, 0, len(exclusions))
	for _, exclusion := range exclusions {
		_, _, intersects := target.intersects(exclusion)
		if intersects {
			relevant = append(relevant, exclusion)
		}
	}
	sort.Slice(relevant, func(i, j int) bool {
		return relevant[i].lower.compare(relevant[j].lower) < 0
	})
	cursor := target.lower
	for _, exclusion := range relevant {
		if exclusion.lower.compare(cursor) > 0 {
			return false
		}
		if exclusion.upper == nil {
			return true
		}
		if exclusion.upper.compare(cursor) > 0 {
			cursor = *exclusion.upper
		}
		if target.upper != nil && cursor.compare(*target.upper) >= 0 {
			return true
		}
	}
	return target.upper != nil && cursor.compare(*target.upper) >= 0
}

type runtimeProfile struct {
	value string
	scope versionRange
}

func sortedRuntimeProfiles(values []string) ([]runtimeProfile, error) {
	profiles := make([]runtimeProfile, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, exists := seen[value]; exists {
			continue
		}
		scope, ok := parseProfileRange(value)
		if !ok {
			return nil, fmt.Errorf("embedded runtime profile %q is malformed", value)
		}
		seen[value] = struct{}{}
		profiles = append(profiles, runtimeProfile{value: value, scope: scope})
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].scope.lower.compare(profiles[j].scope.lower) > 0
	})
	return profiles, nil
}

func parseProfileRange(value string) (versionRange, bool) {
	version, err := parseConstraintVersion("node", strings.TrimSpace(value))
	if err != nil || version.wildcard {
		return versionRange{}, false
	}
	return versionScope(version), true
}

func rangeCanonical(value versionRange) []string {
	if value.upper != nil && value.upper.compare(value.lower.nextPatch()) == 0 {
		return []string{"=" + value.lower.String()}
	}
	result := []string{">=" + value.lower.String()}
	if value.upper != nil {
		result = append(result, "<"+value.upper.String())
	}
	return result
}

func displayScope(version parsedVersion) string {
	switch version.precision {
	case 1:
		return fmt.Sprintf("%d.x", version.value.major)
	case 2:
		return fmt.Sprintf("%d.%d.x", version.value.major, version.value.minor)
	default:
		return version.value.String()
	}
}

func constraintError(code, stack, constraint, detail string) *RuntimeConstraintError {
	return &RuntimeConstraintError{
		ReasonCode: code,
		Stack:      stack,
		Constraint: constraint,
		Detail:     detail,
	}
}

func compareInt(left, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func errorsf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
