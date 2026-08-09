package client

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
	"time"

	"github.com/Luclpor/GophKeeper/internal/vault"
)

// Client performs authenticated requests to a GophKeeper server.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type config struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Option configures a Client during construction.
type Option func(*config)

// WithBaseURL configures the server root URL, for example
// http://localhost:8080.
func WithBaseURL(baseURL string) Option {
	return func(config *config) {
		config.baseURL = baseURL
	}
}

// WithToken configures the bearer token used for authenticated requests.
func WithToken(token string) Option {
	return func(config *config) {
		config.token = token
	}
}

// WithHTTPClient configures the transport used for requests.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(config *config) {
		config.httpClient = httpClient
	}
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

type apiError struct {
	Error string `json:"error"`
}

type syncRequest struct {
	Records []vault.Record `json:"records"`
}

type syncResponse struct {
	Records []vault.Record `json:"records"`
}

// New constructs a Client from functional options.
func New(options ...Option) (*Client, error) {
	config := config{}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}

	if strings.TrimSpace(config.baseURL) == "" {
		return nil, errors.New("base url is required")
	}
	parsed, err := url.Parse(config.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("base url must include scheme and host")
	}
	if config.httpClient == nil {
		config.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		baseURL:    parsed,
		token:      config.token,
		httpClient: config.httpClient,
	}, nil
}

// SetToken updates the bearer token used by authenticated requests.
func (c *Client) SetToken(token string) {
	c.token = token
}

// Token returns the current bearer token.
func (c *Client) Token() string {
	return c.token
}

// Register creates a user account and stores the returned token in the client.
func (c *Client) Register(ctx context.Context, username, password string) (string, error) {
	var response authResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/register", authRequest{
		Username: username,
		Password: password,
	}, &response)
	if err != nil {
		return "", err
	}
	c.token = response.Token
	return response.Token, nil
}

// Login authenticates a user and stores the returned token in the client.
func (c *Client) Login(ctx context.Context, username, password string) (string, error) {
	var response authResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/login", authRequest{
		Username: username,
		Password: password,
	}, &response)
	if err != nil {
		return "", err
	}
	c.token = response.Token
	return response.Token, nil
}

// ListRecords returns all non-deleted encrypted records for the authenticated
// user.
func (c *Client) ListRecords(ctx context.Context) ([]vault.Record, error) {
	var records []vault.Record
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/records", nil, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// GetRecord returns one encrypted record by id.
func (c *Client) GetRecord(ctx context.Context, id string) (vault.Record, error) {
	var record vault.Record
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/records/"+url.PathEscape(id), nil, &record); err != nil {
		return vault.Record{}, err
	}
	return record, nil
}

// PutRecord creates or updates an encrypted record.
func (c *Client) PutRecord(ctx context.Context, record vault.Record) (vault.Record, error) {
	var saved vault.Record
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/records/"+url.PathEscape(record.ID), record, &saved); err != nil {
		return vault.Record{}, err
	}
	return saved, nil
}

// DeleteRecord deletes a record and returns the server tombstone.
func (c *Client) DeleteRecord(ctx context.Context, id string) (vault.Record, error) {
	var tombstone vault.Record
	if err := c.doJSON(ctx, http.MethodDelete, "/api/v1/records/"+url.PathEscape(id), nil, &tombstone); err != nil {
		return vault.Record{}, err
	}
	return tombstone, nil
}

// SyncRecords merges local encrypted records with the server state.
func (c *Client) SyncRecords(ctx context.Context, records []vault.Record) ([]vault.Record, error) {
	var response syncResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/records/sync", syncRequest{Records: records}, &response); err != nil {
		return nil, err
	}
	return response.Records, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		raw, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode >= http.StatusBadRequest {
		return decodeAPIError(response)
	}
	if responseBody == nil {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) endpoint(path string) string {
	endpoint := *c.baseURL
	basePath := strings.TrimRight(endpoint.Path, "/")
	endpoint.Path = basePath + "/" + strings.TrimLeft(path, "/")
	return endpoint.String()
}

func decodeAPIError(response *http.Response) error {
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("server returned %s", response.Status)
	}

	var payload apiError
	if err := json.Unmarshal(raw, &payload); err == nil && payload.Error != "" {
		return fmt.Errorf("server returned %s: %s", response.Status, payload.Error)
	}
	return fmt.Errorf("server returned %s", response.Status)
}
