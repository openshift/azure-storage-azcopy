//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package generated

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"strconv"
	"strings"
)

// ServiceClient contains the methods for the Service group.
// Don't use this type directly, use a constructor function instead.
type ServiceClient struct {
	internal *azcore.Client
	endpoint string
}

// GetProperties - Gets the properties of a storage account's File service, including properties for Storage Analytics metrics
// and CORS (Cross-Origin Resource Sharing) rules.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-05-04
//   - options - ServiceClientGetPropertiesOptions contains the optional parameters for the ServiceClient.GetProperties method.
func (client *ServiceClient) GetProperties(ctx context.Context, options *ServiceClientGetPropertiesOptions) (ServiceClientGetPropertiesResponse, error) {
	var err error
	req, err := client.getPropertiesCreateRequest(ctx, options)
	if err != nil {
		return ServiceClientGetPropertiesResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return ServiceClientGetPropertiesResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return ServiceClientGetPropertiesResponse{}, err
	}
	resp, err := client.getPropertiesHandleResponse(httpResp)
	return resp, err
}

// getPropertiesCreateRequest creates the GetProperties request.
func (client *ServiceClient) getPropertiesCreateRequest(ctx context.Context, options *ServiceClientGetPropertiesOptions) (*policy.Request, error) {
	req, err := runtime.NewRequest(ctx, http.MethodGet, client.endpoint)
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("restype", "service")
	reqQP.Set("comp", "properties")
	if options != nil && options.Timeout != nil {
		reqQP.Set("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["x-ms-version"] = []string{"2024-05-04"}
	req.Raw().Header["Accept"] = []string{"application/xml"}
	return req, nil
}

// getPropertiesHandleResponse handles the GetProperties response.
func (client *ServiceClient) getPropertiesHandleResponse(resp *http.Response) (ServiceClientGetPropertiesResponse, error) {
	result := ServiceClientGetPropertiesResponse{}
	if val := resp.Header.Get("x-ms-request-id"); val != "" {
		result.RequestID = &val
	}
	if val := resp.Header.Get("x-ms-version"); val != "" {
		result.Version = &val
	}
	if err := runtime.UnmarshalAsXML(resp, &result.StorageServiceProperties); err != nil {
		return ServiceClientGetPropertiesResponse{}, err
	}
	return result, nil
}

// NewListSharesSegmentPager - The List Shares Segment operation returns a list of the shares and share snapshots under the
// specified account.
//
// Generated from API version 2024-05-04
//   - options - ServiceClientListSharesSegmentOptions contains the optional parameters for the ServiceClient.NewListSharesSegmentPager
//     method.
//
// listSharesSegmentCreateRequest creates the ListSharesSegment request.
func (client *ServiceClient) ListSharesSegmentCreateRequest(ctx context.Context, options *ServiceClientListSharesSegmentOptions) (*policy.Request, error) {
	req, err := runtime.NewRequest(ctx, http.MethodGet, client.endpoint)
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("comp", "list")
	if options != nil && options.Prefix != nil {
		reqQP.Set("prefix", *options.Prefix)
	}
	if options != nil && options.Marker != nil {
		reqQP.Set("marker", *options.Marker)
	}
	if options != nil && options.Maxresults != nil {
		reqQP.Set("maxresults", strconv.FormatInt(int64(*options.Maxresults), 10))
	}
	if options != nil && options.Include != nil {
		reqQP.Set("include", strings.Join(strings.Fields(strings.Trim(fmt.Sprint(options.Include), "[]")), ","))
	}
	if options != nil && options.Timeout != nil {
		reqQP.Set("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["x-ms-version"] = []string{"2024-05-04"}
	req.Raw().Header["Accept"] = []string{"application/xml"}
	return req, nil
}

// listSharesSegmentHandleResponse handles the ListSharesSegment response.
func (client *ServiceClient) ListSharesSegmentHandleResponse(resp *http.Response) (ServiceClientListSharesSegmentResponse, error) {
	result := ServiceClientListSharesSegmentResponse{}
	if val := resp.Header.Get("x-ms-request-id"); val != "" {
		result.RequestID = &val
	}
	if val := resp.Header.Get("x-ms-version"); val != "" {
		result.Version = &val
	}
	if err := runtime.UnmarshalAsXML(resp, &result.ListSharesResponse); err != nil {
		return ServiceClientListSharesSegmentResponse{}, err
	}
	return result, nil
}

// SetProperties - Sets properties for a storage account's File service endpoint, including properties for Storage Analytics
// metrics and CORS (Cross-Origin Resource Sharing) rules.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-05-04
//   - storageServiceProperties - The StorageService properties.
//   - options - ServiceClientSetPropertiesOptions contains the optional parameters for the ServiceClient.SetProperties method.
func (client *ServiceClient) SetProperties(ctx context.Context, storageServiceProperties StorageServiceProperties, options *ServiceClientSetPropertiesOptions) (ServiceClientSetPropertiesResponse, error) {
	var err error
	req, err := client.setPropertiesCreateRequest(ctx, storageServiceProperties, options)
	if err != nil {
		return ServiceClientSetPropertiesResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return ServiceClientSetPropertiesResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusAccepted) {
		err = runtime.NewResponseError(httpResp)
		return ServiceClientSetPropertiesResponse{}, err
	}
	resp, err := client.setPropertiesHandleResponse(httpResp)
	return resp, err
}

// setPropertiesCreateRequest creates the SetProperties request.
func (client *ServiceClient) setPropertiesCreateRequest(ctx context.Context, storageServiceProperties StorageServiceProperties, options *ServiceClientSetPropertiesOptions) (*policy.Request, error) {
	req, err := runtime.NewRequest(ctx, http.MethodPut, client.endpoint)
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("restype", "service")
	reqQP.Set("comp", "properties")
	if options != nil && options.Timeout != nil {
		reqQP.Set("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["x-ms-version"] = []string{"2024-05-04"}
	req.Raw().Header["Accept"] = []string{"application/xml"}
	if err := runtime.MarshalAsXML(req, storageServiceProperties); err != nil {
		return nil, err
	}
	return req, nil
}

// setPropertiesHandleResponse handles the SetProperties response.
func (client *ServiceClient) setPropertiesHandleResponse(resp *http.Response) (ServiceClientSetPropertiesResponse, error) {
	result := ServiceClientSetPropertiesResponse{}
	if val := resp.Header.Get("x-ms-request-id"); val != "" {
		result.RequestID = &val
	}
	if val := resp.Header.Get("x-ms-version"); val != "" {
		result.Version = &val
	}
	return result, nil
}