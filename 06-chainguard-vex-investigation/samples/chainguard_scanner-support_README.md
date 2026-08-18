# Vulnerability Scanner Support

This repository provides resources intended for software engineers that work on vulnerability scanners, in order to help them correctly implement support for:

- **Chainguard Images** and the Wolfi (un)distribution
- **Chainguard Libraries** for Python, JavaScript, and other language ecosystems

## Resources

### Chainguard Images and Wolfi

If you're unfamiliar with Chainguard Images, Wolfi, or the security data published by Chainguard, take a quick read through [Foundational Concepts](./docs/foundational_concepts.md).

Next, to learn how to implement support for Chainguard Images and Wolfi in your vulnerability scanner, look at [Scanning Implementation](./docs/scanning_implementation.md).

Finally, when you're ready to verify that your scanner produces the correct results for a given scan target, look at [Verifying Scan Results](./docs/verifying_scan_results.md).

**IMPORTANT:** In order to officially support Chainguard Images and Wolfi, your scanner must meet the criteria defined in [Verifying Scan Results](./docs/verifying_scan_results.md).

### Chainguard Libraries

Chainguard Libraries provides secure, curated versions of open source libraries with CVE remediation for Python, JavaScript, and other language ecosystems.

If you're unfamiliar with Chainguard Libraries, start with [Libraries Foundational Concepts](./libraries/foundational_concepts.md) to understand what Libraries are and how CVE remediation works.

Next, to learn how to integrate Chainguard's VEX feed in your vulnerability scanner, look at [Libraries Scanning Implementation](./libraries/scanning_implementation.md).

### Scanner Audit Tool

The `scanner-audit` tool is a Go-based CLI utility that allows organizations responsible for specific scanner implementations to validate their scanner against Chainguard's provided test cases. This tool helps ensure your scanner correctly identifies vulnerabilities in Chainguard Images and packages according to the official support criteria, producing a detailed HTML report with test results.

For detailed usage instructions and implementation details, please see the [   `scanner-audit/`](./scanner-audit/README.md) directory.
