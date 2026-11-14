package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// client is a minimal JSON client for the API server (no client-go).
type client struct {
	server string
	http   *http.Client
	token  string
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("API server: HTTP %d: %s", e.code, e.body) }

func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

func (c client) request(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(raw)
	}
	u := strings.TrimRight(c.server, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(msg))}
	}
	return resp, nil
}

func (c client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	resp, err := c.request(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return err
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

type objectMeta struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid"`
	Labels            map[string]string `json:"labels"`
	DeletionTimestamp *string           `json:"deletionTimestamp"`
}

type containerState struct {
	Waiting *struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"waiting"`
	Running    *struct{} `json:"running"`
	Terminated *struct {
		ExitCode int32  `json:"exitCode"`
		Reason   string `json:"reason"`
		Message  string `json:"message"`
	} `json:"terminated"`
}

type pod struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		Reason            string `json:"reason"`
		Message           string `json:"message"`
		ContainerStatuses []struct {
			Name  string         `json:"name"`
			State containerState `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type podList struct {
	Items []pod `json:"items"`
}

type object struct {
	Metadata objectMeta `json:"metadata"`
}

type job struct {
	Metadata objectMeta `json:"metadata"`
	Status   struct {
		Conditions []jobCondition `json:"conditions"`
	} `json:"status"`
}

type jobCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// failed returns the condition with which the Job controller gave up on the
// Job: FailureTarget, which it sets first, or Failed.
func (j job) failed() (jobCondition, bool) {
	for _, c := range j.Status.Conditions {
		if (c.Type == "FailureTarget" || c.Type == "Failed") && c.Status == "True" {
			return c, true
		}
	}
	return jobCondition{}, false
}
