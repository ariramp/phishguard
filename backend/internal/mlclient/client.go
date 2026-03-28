package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client interface {
	PredictURL(ctx context.Context, url string, subject string, snippet string) (float32, int16, string, map[string]any, error)
	Status(ctx context.Context) (map[string]any, error)
}

type httpClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTP(baseURL string, timeout time.Duration) Client {
	return &httpClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

type predictReq struct {
	URL     string `json:"url"`
	Subject string `json:"subject"`
	Snippet string `json:"snippet"`
}

type predictResp struct {
	Score        float32        `json:"score"`
	Risk         int16          `json:"risk"`
	ModelVersion string         `json:"model_version"`
	Features     map[string]any `json:"features"`
}

func (h *httpClient) PredictURL(ctx context.Context, url string, subject string, snippet string) (float32, int16, string, map[string]any, error) {
	reqBody, err := json.Marshal(predictReq{
		URL:     url,
		Subject: subject,
		Snippet: snippet,
	})
	if err != nil {
		return 0, 0, "", nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/v1/predict/url", bytes.NewReader(reqBody))
	if err != nil {
		return 0, 0, "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, 0, "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, 0, "", nil, fmt.Errorf("ml service returned %s: %s", resp.Status, string(body))
	}

	var pr predictResp
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return 0, 0, "", nil, err
	}

	return pr.Score, pr.Risk, pr.ModelVersion, pr.Features, nil
}

func (h *httpClient) Status(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+"/v1/model", nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ml service returned %s: %s", resp.Status, string(body))
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return payload, nil
}
