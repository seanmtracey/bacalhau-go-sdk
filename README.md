# Bacalhau Go SDK

This SDK provides a simple, high-level interface for interacting with a [Bacalhau](https://bacalhau.org) orchestrator from a Go application. It allows you to list nodes, submit jobs, query job results, inspect job history, and retrieve agent metadata — all using structured, typed methods.

This package has been designed and tested to work with Bacalhau `v1.7.0` or greater. 

The best experience is with an [Expanso Cloud](https://cloud.expanso.io) Managed Orchestrator. Check it out!

---

## Getting Started

### Installation

First, install the package on your system with
```go
go get github.com/bacalhau-project/bacalhau-go-sdk
```

Import your local module (or your hosted module, e.g., via GitHub):

```go
import bacalhau "github.com/bacalhau-project/bacalhau-go-sdk/pkg/bacalhau-sdk/client"
```

### Example Usage

```go

// Create a client with your credentials and preferences
bClient := bacalhau.New(host, port, secure, accessToken)

// Get a list of Nodes connected to your Orchestrator
nodes, _ := bClient.ListNodes()

// Get info about a specific Node
info, _ := bClient.GetNodeInfo(nodes.Nodes[0].Info.NodeID)

// Load a Job file from disk and send it off for scheduling
jobFileBytes, _ := os.ReadFile("./example.yaml")
jobResp, _ := bClient.CreateJob(string(jobFileBytes), "yaml")

// Get details for that Job
description, _ := bClient.DescribeJob(jobResp.JobID)

// Get results of your Job's execution
results, _ := bClient.GetJobResult(jobResp.JobID)
```

---

## Client Constructor

```go

host := os.Getenv("BACALHAU_HOST") // The hostname of your Bacalhau Orchestrator
port := os.Getenv("BACALHAU_PORT") // The port your Orchestrator is making the API available from: Defaults to 1234
secure := true
accessToken := os.Getenv("BACALHAU_API_TOKEN") // The access token for your orchestrator (if you're using a secure connection).

client := bacalhau.New(host, port, useSecure, accessToken)
```

---

## Available Methods

### `ListNodes()`
Endpoint: `GET /api/v1/orchestrator/nodes`
> Lists all active nodes in the Bacalhau network.
```go
NodeListResponse, err := client.ListNodes()
```

---

### `GetNodeInfo(nodeID string)`
Endpoint: `GET /api/v1/orchestrator/nodes/{nodeID}`
> Fetches detailed information about a specific node.
```go
NodeResponse, err := client.GetNodeInfo("node-id")
```

---

### `CreateJob(jobYaml string, format string)`
Endpoint: `PUT /api/v1/orchestrator/jobs`
> Submits a job to the orchestrator.
- `jobYaml` must be a valid YAML or JSON job spec.
- `format` must be either `yaml` or `json`
```go
CreateJobResponse, err := client.CreateJob(jobYaml, "yaml")
```

---

### `DescribeJob(jobID string)`
Endpoint: `GET /api/v1/orchestrator/jobs/{jobID}`
> Retrieves a full description of a submitted job.
```go
JobDescription, err := client.DescribeJob("job-id")
```

---

### `GetJobResult(jobID string)`
Endpoint: `GET /api/v1/orchestrator/jobs/{jobID}/executions`
> Fetches the `stdout` output from a completed job.
```go
JobExecutionResult, err := client.GetJobResult("job-id")
```

---

### `GetJobHistory(jobID string, parameters map[string]interface{})`
Endpoint: `GET /api/v1/orchestrator/jobs/{jobID}/history`
> Returns a structured timeline of events for a job.
```go
JobHistory, err := client.GetJobHistory("job-id", map[string]interface{}{
  "since": 0,
  "limit": 100,
})
```

---

### `GetJobExecutions(jobID string)`
Endpoint: `GET /api/v1/orchestrator/jobs/{jobID}`
> Lists all executions for a specific job.
```go
map[string]interface{}, err := client.GetJobExecutions("job-id")
```

---

### `IsAlive()`
Endpoint: `GET /api/v1/agent/alive`
> Pings the orchestrator to check if it is alive.
```go
bool, err := client.IsAlive()
```

---

### `GetBacalhauVersion()`
Endpoint: `GET /api/v1/agent/version`
> Returns the Bacalhau version running on the orchestrator.
```go
AgentVersionResponse, err := client.GetBacalhauVersion()
```

---

### `GetAgentNodeInfo()`
Endpoint: `GET /api/v1/agent/node`
> Retrieves agent-level node info (includes capacity, versions, etc.).
```go
NodeInfo, err := client.GetAgentNodeInfo()
```
---

## License
Apache License Version 2.0

---

Built with ❤️ for Bacalhau operators and developers.

