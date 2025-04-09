package bacalhauClient

import (
	"fmt"
	"io"
	"bytes"
	"strings"
	"errors"
	"encoding/json"
	"net/http"
	"net/url"

	"gopkg.in/yaml.v3"
)

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>
// >> Node Structs
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<

type NodeResponse struct {
	Node Node `json:"Node"`
}

type Node struct {
	Info            NodeInfo        `json:"Info"`
	Membership      string          `json:"Membership"`
	Connection      string          `json:"Connection"`
	ConnectionState ConnectionState `json:"ConnectionState"`
}

type NodeInfo struct {
	NodeID            string            `json:"NodeID"`
	NodeType          string            `json:"NodeType"`
	Labels            map[string]string `json:"Labels"`
	SupportedProtocols []string         `json:"SupportedProtocols"`
	ComputeNodeInfo   ComputeNodeInfo   `json:"ComputeNodeInfo"`
	BacalhauVersion   BacalhauVersion   `json:"BacalhauVersion"`
}

type ComputeNodeInfo struct {
	ExecutionEngines   []string         `json:"ExecutionEngines"`
	Publishers         []string         `json:"Publishers"`
	StorageSources     []string         `json:"StorageSources"`
	MaxCapacity        Capacity         `json:"MaxCapacity"`
	QueueCapacity      map[string]any   `json:"QueueCapacity"`
	AvailableCapacity  Capacity         `json:"AvailableCapacity"`
	MaxJobRequirements Capacity         `json:"MaxJobRequirements"`
	RunningExecutions  int              `json:"RunningExecutions"`
	EnqueuedExecutions int              `json:"EnqueuedExecutions"`
	Address            string           `json:"address"`
}

type PeerInfo struct {
	ID string `json:"ID"`
	Addrs []string `json:"Addrs"`
}

type Capacity struct {
	CPU    float64 `json:"CPU"`
	Memory int64   `json:"Memory"`
	Disk   int64   `json:"Disk"`
	GPU    int     `json:"GPU"`
}

type BacalhauVersion struct {
	Major      string `json:"Major"`
	Minor      string `json:"Minor"`
	GitVersion string `json:"GitVersion"`
	GitCommit  string `json:"GitCommit"`
	BuildDate  string `json:"BuildDate"`
	GOOS       string `json:"GOOS"`
	GOARCH     string `json:"GOARCH"`
}

type ConnectionState struct {
	Status            string `json:"Status"`
	LastHeartbeat     string `json:"LastHeartbeat"`
	ConnectedSince    string `json:"ConnectedSince"`
	DisconnectedSince string `json:"DisconnectedSince"`
}

type NodeListResponse struct {
	NextToken string
	Nodes     []Node
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>
// >> Job Structs
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<

type JobDescription struct {
	Job Job `json:"Job"`
}

type Job struct {
	ID          string                 `json:"ID"`
	Name        string                 `json:"Name"`
	Namespace   string                 `json:"Namespace"`
	Type        string                 `json:"Type"`
	Priority    int                    `json:"Priority"`
	Count       int                    `json:"Count"`
	Constraints []interface{}          `json:"Constraints"` // adjust to a struct if needed
	Meta        map[string]string      `json:"Meta"`
	Labels      map[string]string      `json:"Labels"`
	Tasks       []Task                 `json:"Tasks"`
	State       JobState               `json:"State"`
	Version     int                    `json:"Version"`
	Revision    int                    `json:"Revision"`
	CreateTime  int64                  `json:"CreateTime"`
	ModifyTime  int64                  `json:"ModifyTime"`
}

type Task struct {
	Name         string                 `json:"Name"`
	Engine       Engine                 `json:"Engine"`
	Publisher    Publisher              `json:"Publisher"`
	Env          map[string]string      `json:"Env"`
	Meta         map[string]string      `json:"Meta"`
	InputSources []interface{}          `json:"InputSources"` // fill in types if known
	ResultPaths  []interface{}          `json:"ResultPaths"`
	Resources    Resources              `json:"Resources"`
	Network      Network                `json:"Network"`
	Timeouts     Timeouts               `json:"Timeouts"`
}

type Engine struct {
	Type   string                 `json:"Type"`
	Params EngineParams           `json:"Params"`
}

type EngineParams struct {
	Entrypoint []string           `json:"Entrypoint"`
	Image      string             `json:"Image"`
	Parameters []string           `json:"Parameters"`
	EnvironmentVariables []string `json:"EnvironmentVariables"`
}

type Publisher struct {
	Type   string                 `json:"Type"`
	Params map[string]interface{} `json:"Params"`
}

type Resources struct {
	CPU    string `json:"CPU"`
	Memory string `json:"Memory"`
	Disk   string `json:"Disk"`
	GPU    string `json:"GPU"`
}

type Network struct {
	Type string `json:"Type"`
}

type Timeouts struct {
	ExecutionTimeout int `json:"ExecutionTimeout"`
}

type JobState struct {
	StateType string `json:"StateType"`
	Message   string `json:"Message"`
}

type JobExecutionResult struct {
	JobID       string `json:"JobID"`
	ExecutionID string `json:"ExecutionID"`
	Stdout      string `json:"Stdout"`
}

type CreateJobResponse struct {
	JobID        string   `json:"JobID"`
	EvaluationID string   `json:"ExecutionID"`
	Warnings     []string `json:"Warnings"`
}

type JobHistory struct {
	NextToken string           `json:"NextToken"`
	Items   []HistoryEntry   `json:"Items"`
}

type HistoryEntry struct {
	Type           string          `json:"Type"`
	JobID          string          `json:"JobID"`
	NodeID         string          `json:"NodeID"`
	ExecutionID    string          `json:"ExecutionID"`
	JobState       interface{}     `json:"JobState"` // nullable; can change to specific type if known
	ExecutionState ExecutionState  `json:"ExecutionState"`
	NewRevision    int             `json:"NewRevision"`
	Comment        string          `json:"Comment"`
	Time           string          `json:"Time"` // can be time.Time with custom unmarshal if needed
}

type ExecutionState struct {
	Previous int `json:"Previous"`
	New      int `json:"New"`
}

type JobHistoryFilters struct {
	Since        int
	Event_type   string
	Execution_ID string
	Node_ID      string
	Limit        int
	Next_token   string
}

type StopJobResponse struct {
	EvaluationID string `json:"EvaluationID"`
}

type JobExecutions struct {
	NextToken string        `json:"NextToken"`
	Items     []JobSummary  `json:"Items"`
}

type JobSummary struct {
	ID          string                 `json:"ID"`
	Name        string                 `json:"Name"`
	Namespace   string                 `json:"Namespace"`
	Type        string                 `json:"Type"`
	Priority    int                    `json:"Priority"`
	Count       int                    `json:"Count"`
	Constraints []interface{}          `json:"Constraints"`
	Meta        map[string]string      `json:"Meta"`
	Labels      map[string]string      `json:"Labels"`
	Tasks       []JobTask              `json:"Tasks"`
	State       JobState               `json:"State"`
	Version     int                    `json:"Version"`
	Revision    int                    `json:"Revision"`
	CreateTime  int64                  `json:"CreateTime"`
	ModifyTime  int64                  `json:"ModifyTime"`
}

type JobTask struct {
	Name      string        `json:"Name"`
	Engine    TaskEngine    `json:"Engine"`
	Publisher TaskPublisher `json:"Publisher"`
	Resources TaskResources `json:"Resources"`
	Network   TaskNetwork   `json:"Network"`
	Timeouts  TaskTimeouts  `json:"Timeouts"`
}

type TaskEngine struct {
	Type   string            `json:"Type"`
	Params EngineParams      `json:"Params"`
}

type TaskPublisher struct {
	Type string `json:"Type"`
}

type TaskResources struct {
	CPU    string `json:"CPU"`
	Memory string `json:"Memory"`
}

type TaskNetwork struct {
	Type string `json:"Type"`
}

type TaskTimeouts struct {
	// Empty in your examples, can be filled out later
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>
// >> Agent Structs
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<

type AgentStatus struct {
	Status string `json:"Status"`
}

type AgentVersionResponse struct {
	Major string `json:"Major"`
	Minor string `json:"Minor"`
	GitVersion string `json:"GitVersion"`
	GitCommit string `json:"GitCommit"`
	BuildDate string `json:"BuildDate"`
	GOOS string `json:"GOOS"`
	GARCH string `json:"GOARCH"`
}

type AgentNodeInfo struct {
	PeerInfo        PeerInfo              `json:"PeerInfo"`
	NodeType        string                `json:"NodeType"`
	Labels          map[string]string     `json:"Labels"`
	ComputeNodeInfo ComputeNodeInfo       `json:"ComputeNodeInfo"`
	BacalhauVersion BacalhauVersion       `json:"BacalhauVersion"`
}


// >>>>>>>>>>>>>>>>>>>>>>>>>>>>
// >> Client Struct
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<

type Client struct {
	Host        string
	Port        string
	UseSecure   bool
	AccessToken string
}

func New(host, port string, useSecure bool, accessToken string) *Client {

	return &Client{
		Host:        host,
		Port:        port,
		UseSecure:   useSecure,
		AccessToken: accessToken,
	}

}

func (c *Client) ListNodes() (NodeListResponse, error) {
	
	nodesListURL := fmt.Sprintf("%s/api/v1/orchestrator/nodes", c.constructOrchestratorURL())
	
	req, err := http.NewRequest("GET", nodesListURL, nil)
	if err != nil {
		return NodeListResponse{}, err
	}

	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer " + c.AccessToken)
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NodeListResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return NodeListResponse{}, fmt.Errorf("failed to fetch node list: %s", string(body))
	}

	var result NodeListResponse
	err = json.NewDecoder(resp.Body).Decode(&result)

	return result, err

}

func (c *Client) GetNodeInfo(nodeID string) (NodeResponse, error) {

	url := fmt.Sprintf("%s/api/v1/orchestrator/nodes/%s", c.constructOrchestratorURL(), nodeID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return NodeResponse{}, err
	}

	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NodeResponse{}, err
	}
	defer resp.Body.Close()

	var nodesList NodeResponse
	err = json.NewDecoder(resp.Body).Decode(&nodesList)

	return nodesList, err

}

func (c *Client) DescribeJob(JobID string) (JobDescription, error) {

	if JobID == ""{
		return JobDescription{}, errors.New(`"JobID" parameter cannot be an empty string.`)
	}

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs/%s", c.constructOrchestratorURL(), JobID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating job description request:", err)
		return JobDescription{}, errors.New( fmt.Sprintf("Could not describe Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error getting job description:", err)
		return JobDescription{}, errors.New( fmt.Sprintf("Could not describe Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	var response JobDescription
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Println("Error decoding job response:", err)
		return JobDescription{}, errors.New( fmt.Sprintf("Could not describe Job. Error: %s", err.Error()) )
	}

	return response, nil

}

func (c *Client) CreateJob(Job string, format string) (CreateJobResponse, error) {

	if format != "yaml" && format != "json" {
		return CreateJobResponse{}, errors.New( fmt.Sprintf(`"format" parameter must be either "json" or "yaml". The passed value was "%s"`, format ) )
	}

	if format == "yaml" {
		jsonJob, conversionErr := ConvertYamlToJSON(Job)

		if conversionErr != nil {
			return CreateJobResponse{}, conversionErr
		} else {
			Job = jsonJob
		}

	}
	
	var jsonObj map[string]interface{}
	
	if err := json.Unmarshal([]byte(Job), &jsonObj); err != nil {
		return CreateJobResponse{}, errors.New(fmt.Sprintf("Could not create Job. Error: %s", err.Error()))
	}

	if _, ok := jsonObj["Job"]; !ok {

		wrappedJob, wrapErr := wrapJob(Job)

		if wrapErr != nil {
			return CreateJobResponse{}, errors.New(fmt.Sprintf("Could not create Job. Error: %s", wrapErr.Error()))
		}

		Job = wrappedJob

	}

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs", c.constructOrchestratorURL())
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer([]byte(Job)))
	if err != nil {
		fmt.Println("Error creating job request:", err)
		return CreateJobResponse{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending job:", err)
		return CreateJobResponse{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	var response CreateJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Println("Error decoding job response:", err)
		return CreateJobResponse{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}

	return response, nil

}

func (c *Client) StopJob(JobID, reason string) (StopJobResponse, error) {

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs/%s", c.constructOrchestratorURL(), JobID)
	payload := map[string]string{ "reason": reason }
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(data))
	if err != nil {
		return StopJobResponse{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return StopJobResponse{}, err
	}
	defer resp.Body.Close()

	var response StopJobResponse

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Println("Error parsing response from stopping Job:", err.Error())
		return StopJobResponse{}, errors.New( fmt.Sprintf("Could not stop Job. Error: %s", err.Error()) )
	}

	return response, nil

}

func (c *Client) GetJobHistory(JobID string, parameters map[string]interface{}) (JobHistory, error) {
	
	filters, _ := constructURLQueryParameters(parameters)

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs/%s/history%s", c.constructOrchestratorURL(), JobID, filters)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return JobHistory{}, fmt.Errorf("Could not create job history request: %s", err.Error())
	}

	req.Header.Set("Content-Type", "application/json")

	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return JobHistory{}, fmt.Errorf("Could not send job history request: %s", err.Error())
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return JobHistory{}, fmt.Errorf("Could not read job history response: %s", err.Error())
	}

	// fmt.Println("Raw response body:\n", string(bodyBytes))

	var response JobHistory
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return JobHistory{}, fmt.Errorf("Could not decode job history: %s", err.Error())
	}

	return response, nil

}

func (c *Client) GetJobResult(JobID string) (JobExecutionResult, error) {

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs/%s/executions", c.constructOrchestratorURL(), JobID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return JobExecutionResult{}, err
	}
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return JobExecutionResult{}, err
	}
	defer resp.Body.Close()

	var executions struct {
		Items []struct {
			ID        string `json:"ID"`
			RunOutput struct {
				Stdout string `json:"Stdout"`
			} `json:"RunOutput"`
		} `json:"Items"`
	}

	err = json.NewDecoder(resp.Body).Decode(&executions)
	if err != nil {
		return JobExecutionResult{}, err
	}

	for _, exec := range executions.Items {

		if exec.RunOutput.Stdout != "" {
			return JobExecutionResult{
				JobID:       JobID,
				ExecutionID: exec.ID,
				Stdout:      exec.RunOutput.Stdout,
			}, nil
		}

	}

	return JobExecutionResult{}, fmt.Errorf("no executions with stdout found")

}

func (c *Client) GetJobExecutions(jobID string) (JobExecutions, error) {

	url := fmt.Sprintf("%s/api/v1/orchestrator/jobs", c.constructOrchestratorURL())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating job request:", err)
		return JobExecutions{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending job:", err)
		return JobExecutions{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return JobExecutions{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var response JobExecutions
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return JobExecutions{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil

}

func (c *Client) IsAlive() (AgentStatus, error) {

	url := fmt.Sprintf("%s/api/v1/agent/alive", c.constructOrchestratorURL())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating job request:", err)
		return AgentStatus{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending job:", err)
		return AgentStatus{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return AgentStatus{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// fmt.Println("Raw response body:\n", string(bodyBytes))

	// Decode JSON into map
	var response AgentStatus
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return AgentStatus{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil

}

func (c *Client) GetBacalhauVersion() (AgentVersionResponse, error) {

	url := fmt.Sprintf("%s/api/v1/agent/version", c.constructOrchestratorURL())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating job request:", err)
		return AgentVersionResponse{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending job:", err)
		return AgentVersionResponse{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return AgentVersionResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decode JSON into map
	var response AgentVersionResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return AgentVersionResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil

}

func (c *Client) GetAgentNodeInfo() (NodeInfo, error) {

	url := fmt.Sprintf("%s/api/v1/agent/node", c.constructOrchestratorURL())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating job request:", err)
		return NodeInfo{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if c.UseSecure && c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending job:", err)
		return NodeInfo{}, errors.New( fmt.Sprintf("Could not create Job. Error: %s", err.Error()) )
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return NodeInfo{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decode JSON into map
	var response NodeInfo
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return NodeInfo{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil

}

// --------------------
// Helper functions
// --------------------

func wrapJob(jobSpec string) (string, error) {
	
	var original map[string]interface{}
	
	if err := json.Unmarshal([]byte(jobSpec), &original); err != nil {
		return "", err
	}

	wrapped := map[string]interface{}{"Job": original}
	out, err := json.Marshal(wrapped)
	
	return string(out), err

}

func ConvertYamlToJSON(yamlFile string) (string, error) {

	yamlBytes := []byte(yamlFile)

	var yamlContent map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &yamlContent); err != nil {
		return "", fmt.Errorf("An error occurred parsing the YAML: %s", err.Error())
	}

	jsonBytes, err := json.Marshal(yamlContent)
	if err != nil {
		return "", fmt.Errorf("An error occurred converting YAML to JSON: %s", err.Error())
	}

	return string(jsonBytes), nil

}

func constructURLQueryParameters(parameters map[string]interface{}) (string, error) {
	
	if len(parameters) == 0 {
		return "", nil
	}

	var urlElements []string

	for key, value := range parameters {
		keyStr := url.QueryEscape(fmt.Sprintf("%v", strings.ToLower(key) ) )
		valStr := url.QueryEscape(fmt.Sprintf("%v", value))
		urlElements = append(urlElements, fmt.Sprintf("%s=%s", keyStr, valStr))
	}

	queryString := "?" + strings.Join(urlElements, "&")

	return queryString, nil

}

func (c *Client) constructOrchestratorURL() string {

	protocol := "http"
	
	if c.UseSecure {
		protocol = "https"
	}

	orchURL := fmt.Sprintf("%s://%s:%s", protocol, c.Host, c.Port)
	
	return orchURL

}