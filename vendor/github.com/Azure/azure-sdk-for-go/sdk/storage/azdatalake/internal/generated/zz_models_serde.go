// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package generated

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"reflect"
	"strconv"
	"time"
)

// MarshalJSON implements the json.Marshaller interface for type ACLFailedEntry.
func (a ACLFailedEntry) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "errorMessage", a.ErrorMessage)
	populate(objectMap, "name", a.Name)
	populate(objectMap, "type", a.Type)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type ACLFailedEntry.
func (a *ACLFailedEntry) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", a, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "errorMessage":
			err = unpopulate(val, "ErrorMessage", &a.ErrorMessage)
			delete(rawMsg, key)
		case "name":
			err = unpopulate(val, "Name", &a.Name)
			delete(rawMsg, key)
		case "type":
			err = unpopulate(val, "Type", &a.Type)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", a, err)
		}
	}
	return nil
}

// MarshalXML implements the xml.Marshaller interface for type PathHierarchyListSegment.
func (b PathHierarchyListSegment) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	type alias PathHierarchyListSegment
	aux := &struct {
		*alias
		PathItems    *[]*PathItemInternal `xml:"Blob"`
		PathPrefixes *[]*PathPrefix       `xml:"PathPrefix"`
	}{
		alias: (*alias)(&b),
	}
	if b.PathItems != nil {
		aux.PathItems = &b.PathItems
	}
	if b.PathPrefixes != nil {
		aux.PathPrefixes = &b.PathPrefixes
	}
	return enc.EncodeElement(aux, start)
}

// MarshalXML implements the xml.Marshaller interface for type PathPropertiesInternal.
func (b PathPropertiesInternal) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	type alias PathPropertiesInternal
	aux := &struct {
		*alias
		AccessTierChangeTime *dateTimeRFC1123 `xml:"AccessTierChangeTime"`
		ContentMD5           *string          `xml:"Content-MD5"`
		CopyCompletionTime   *dateTimeRFC1123 `xml:"CopyCompletionTime"`
		CreationTime         *dateTimeRFC1123 `xml:"Creation-Time"`
		DeleteTime           *dateTimeRFC1123 `xml:"DeleteTime"`
		DeletedTime          *dateTimeRFC1123 `xml:"DeletedTime"`
		ExpiresOn            *dateTimeRFC1123 `xml:"Expiry-Time"`
		LastAccessedOn       *dateTimeRFC1123 `xml:"LastAccessTime"`
		LastModified         *dateTimeRFC1123 `xml:"Last-Modified"`
	}{
		alias:                (*alias)(&b),
		AccessTierChangeTime: (*dateTimeRFC1123)(b.AccessTierChangeTime),
		CopyCompletionTime:   (*dateTimeRFC1123)(b.CopyCompletionTime),
		CreationTime:         (*dateTimeRFC1123)(b.CreationTime),
		DeleteTime:           (*dateTimeRFC1123)(b.DeleteTime),
		DeletedTime:          (*dateTimeRFC1123)(b.DeletedTime),
		ExpiresOn:            (*dateTimeRFC1123)(b.ExpiresOn),
		LastAccessedOn:       (*dateTimeRFC1123)(b.LastAccessedOn),
		LastModified:         (*dateTimeRFC1123)(b.LastModified),
	}
	if b.ContentMD5 != nil {
		encodedContentMD5 := runtime.EncodeByteArray(b.ContentMD5, runtime.Base64StdFormat)
		aux.ContentMD5 = &encodedContentMD5
	}
	return enc.EncodeElement(aux, start)
}

// UnmarshalXML implements the xml.Unmarshaller interface for type PathPropertiesInternal.
func (b *PathPropertiesInternal) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	type alias PathPropertiesInternal
	aux := &struct {
		*alias
		AccessTierChangeTime *dateTimeRFC1123 `xml:"AccessTierChangeTime"`
		ContentMD5           *string          `xml:"Content-MD5"`
		CopyCompletionTime   *dateTimeRFC1123 `xml:"CopyCompletionTime"`
		CreationTime         *dateTimeRFC1123 `xml:"Creation-Time"`
		DeleteTime           *dateTimeRFC1123 `xml:"DeleteTime"`
		DeletedTime          *dateTimeRFC1123 `xml:"DeletedTime"`
		ExpiresOn            *dateTimeRFC1123 `xml:"Expiry-Time"`
		LastAccessedOn       *dateTimeRFC1123 `xml:"LastAccessTime"`
		LastModified         *dateTimeRFC1123 `xml:"Last-Modified"`
	}{
		alias: (*alias)(b),
	}
	if err := dec.DecodeElement(aux, &start); err != nil {
		return err
	}
	if aux.AccessTierChangeTime != nil && !(*time.Time)(aux.AccessTierChangeTime).IsZero() {
		b.AccessTierChangeTime = (*time.Time)(aux.AccessTierChangeTime)
	}
	if aux.ContentMD5 != nil {
		if err := runtime.DecodeByteArray(*aux.ContentMD5, &b.ContentMD5, runtime.Base64StdFormat); err != nil {
			return err
		}
	}
	if aux.CopyCompletionTime != nil && !(*time.Time)(aux.CopyCompletionTime).IsZero() {
		b.CopyCompletionTime = (*time.Time)(aux.CopyCompletionTime)
	}
	if aux.CreationTime != nil && !(*time.Time)(aux.CreationTime).IsZero() {
		b.CreationTime = (*time.Time)(aux.CreationTime)
	}
	if aux.DeleteTime != nil && !(*time.Time)(aux.DeleteTime).IsZero() {
		b.DeleteTime = (*time.Time)(aux.DeleteTime)
	}
	if aux.DeletedTime != nil && !(*time.Time)(aux.DeletedTime).IsZero() {
		b.DeletedTime = (*time.Time)(aux.DeletedTime)
	}
	if aux.ExpiresOn != nil && !(*time.Time)(aux.ExpiresOn).IsZero() {
		b.ExpiresOn = (*time.Time)(aux.ExpiresOn)
	}
	if aux.LastAccessedOn != nil && !(*time.Time)(aux.LastAccessedOn).IsZero() {
		b.LastAccessedOn = (*time.Time)(aux.LastAccessedOn)
	}
	if aux.LastModified != nil && !(*time.Time)(aux.LastModified).IsZero() {
		b.LastModified = (*time.Time)(aux.LastModified)
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type FileSystem.
func (f FileSystem) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "eTag", f.ETag)
	populate(objectMap, "lastModified", f.LastModified)
	populate(objectMap, "name", f.Name)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type FileSystem.
func (f *FileSystem) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", f, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "eTag":
			err = unpopulate(val, "ETag", &f.ETag)
			delete(rawMsg, key)
		case "lastModified":
			err = unpopulate(val, "LastModified", &f.LastModified)
			delete(rawMsg, key)
		case "name":
			err = unpopulate(val, "Name", &f.Name)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", f, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type FileSystemList.
func (f FileSystemList) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "filesystems", f.Filesystems)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type FileSystemList.
func (f *FileSystemList) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", f, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "filesystems":
			err = unpopulate(val, "Filesystems", &f.Filesystems)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", f, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type Path.
func (p Path) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "contentLength", p.ContentLength)
	populate(objectMap, "creationTime", p.CreationTime)
	populate(objectMap, "etag", p.ETag)
	populate(objectMap, "EncryptionContext", p.EncryptionContext)
	populate(objectMap, "EncryptionScope", p.EncryptionScope)
	populate(objectMap, "expiryTime", p.ExpiryTime)
	populate(objectMap, "group", p.Group)
	populate(objectMap, "isDirectory", p.IsDirectory)
	populate(objectMap, "lastModified", p.LastModified)
	populate(objectMap, "name", p.Name)
	populate(objectMap, "owner", p.Owner)
	populate(objectMap, "permissions", p.Permissions)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type Path.
func (p *Path) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", p, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "contentLength":
			var rawVal string
			err = unpopulate(val, "ContentLength", &rawVal)
			intVal, _ := strconv.ParseInt(rawVal, 10, 64)
			p.ContentLength = &intVal
			delete(rawMsg, key)
		case "creationTime":
			err = unpopulate(val, "CreationTime", &p.CreationTime)
			delete(rawMsg, key)
		case "etag":
			err = unpopulate(val, "ETag", &p.ETag)
			delete(rawMsg, key)
		case "EncryptionContext":
			err = unpopulate(val, "EncryptionContext", &p.EncryptionContext)
			delete(rawMsg, key)
		case "EncryptionScope":
			err = unpopulate(val, "EncryptionScope", &p.EncryptionScope)
			delete(rawMsg, key)
		case "expiryTime":
			err = unpopulate(val, "ExpiryTime", &p.ExpiryTime)
			delete(rawMsg, key)
		case "group":
			err = unpopulate(val, "Group", &p.Group)
			delete(rawMsg, key)
		case "isDirectory":
			var rawVal string
			err = unpopulate(val, "IsDirectory", &rawVal)
			boolVal, _ := strconv.ParseBool(rawVal)
			p.IsDirectory = &boolVal
			delete(rawMsg, key)
		case "lastModified":
			err = unpopulate(val, "LastModified", &p.LastModified)
			delete(rawMsg, key)
		case "name":
			err = unpopulate(val, "Name", &p.Name)
			delete(rawMsg, key)
		case "owner":
			err = unpopulate(val, "Owner", &p.Owner)
			delete(rawMsg, key)
		case "permissions":
			err = unpopulate(val, "Permissions", &p.Permissions)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", p, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type PathList.
func (p PathList) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "paths", p.Paths)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type PathList.
func (p *PathList) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", p, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "paths":
			err = unpopulate(val, "Paths", &p.Paths)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", p, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type SetAccessControlRecursiveResponse.
func (s SetAccessControlRecursiveResponse) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "directoriesSuccessful", s.DirectoriesSuccessful)
	populate(objectMap, "failedEntries", s.FailedEntries)
	populate(objectMap, "failureCount", s.FailureCount)
	populate(objectMap, "filesSuccessful", s.FilesSuccessful)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type SetAccessControlRecursiveResponse.
func (s *SetAccessControlRecursiveResponse) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", s, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "directoriesSuccessful":
			err = unpopulate(val, "DirectoriesSuccessful", &s.DirectoriesSuccessful)
			delete(rawMsg, key)
		case "failedEntries":
			err = unpopulate(val, "FailedEntries", &s.FailedEntries)
			delete(rawMsg, key)
		case "failureCount":
			err = unpopulate(val, "FailureCount", &s.FailureCount)
			delete(rawMsg, key)
		case "filesSuccessful":
			err = unpopulate(val, "FilesSuccessful", &s.FilesSuccessful)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", s, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type StorageError.
func (s StorageError) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "error", s.Error)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type StorageError.
func (s *StorageError) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", s, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "error":
			err = unpopulate(val, "Error", &s.Error)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", s, err)
		}
	}
	return nil
}

// MarshalJSON implements the json.Marshaller interface for type StorageErrorError.
func (s StorageErrorError) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]any)
	populate(objectMap, "Code", s.Code)
	populate(objectMap, "Message", s.Message)
	return json.Marshal(objectMap)
}

// UnmarshalJSON implements the json.Unmarshaller interface for type StorageErrorError.
func (s *StorageErrorError) UnmarshalJSON(data []byte) error {
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return fmt.Errorf("unmarshalling type %T: %v", s, err)
	}
	for key, val := range rawMsg {
		var err error
		switch key {
		case "Code":
			err = unpopulate(val, "Code", &s.Code)
			delete(rawMsg, key)
		case "Message":
			err = unpopulate(val, "Message", &s.Message)
			delete(rawMsg, key)
		}
		if err != nil {
			return fmt.Errorf("unmarshalling type %T: %v", s, err)
		}
	}
	return nil
}

func populate(m map[string]any, k string, v any) {
	if v == nil {
		return
	} else if azcore.IsNullValue(v) {
		m[k] = nil
	} else if !reflect.ValueOf(v).IsNil() {
		m[k] = v
	}
}

func unpopulate(data json.RawMessage, fn string, v any) error {
	if data == nil || string(data) == "null" {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("struct field %s: %v", fn, err)
	}
	return nil
}