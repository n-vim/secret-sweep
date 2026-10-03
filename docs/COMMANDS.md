# SecretSweep Commands

## scan

```bash
secretsweep scan .
```

Scans a repository and prints a terminal summary.

Useful options:

```bash
secretsweep scan . --limit 50
secretsweep scan . --fail-on high
secretsweep scan . --config .secretsweep.yaml
```

## files

```bash
secretsweep files .
```

Shows risky secret-related files such as `.env`, `.pem`, `.key`, and private key files.

## env

```bash
secretsweep env .
```

Creates a safe `.env.example` file from a local `.env` file.

## report

```bash
secretsweep report . --format markdown --output SECURITY_REPORT.md
secretsweep report . --format json --output secretsweep-report.json
secretsweep report . --format html --output secretsweep-report.html
```

Generates security reports.

## clean-example

```bash
secretsweep clean-example .
```

Creates `.env.example` and appends recommended secret rules to `.gitignore`.

## init

```bash
secretsweep init
```

Creates `.secretsweep.yaml`.

## config

```bash
secretsweep config
```

Prints the active configuration.
