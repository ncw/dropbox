/*
** Copyright (c) 2014 Arnaud Ysmal.  All Rights Reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
** OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
 */

// Package dropbox implements the Dropbox core API.
package dropbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/stacktic-goauth2/oauth"
)

var ErrNotAuth = errors.New("Authentication required")

// Information about the user account.
type Account struct {
	ReferralLink string `json:"referral_link"` // URL for referral.
	DisplayName  string `json:"display_name"`  // User name.
	Uid          int    `json:"uid"`           // User account ID.
	Country      string `json:"country"`       // Country ISO code.
	QuotaInfo    struct {
		Shared int64 `json:"shared"` // Quota for shared files.
		Quota  int64 `json:"quota"`  // Quota in bytes.
		Normal int64 `json:"normal"` // Quota for non-shared files.
	} `json:"quota_info"`
}

// Reply of copy_ref.
type CopyRef struct {
	CopyRef string `json:"copy_ref"` // Reference to use on fileops/copy.
	Expires string `json:"expires"`  // Expiration date.
}

// Reply of delta.
type DeltaPage struct {
	Reset   bool         // if true the local state must be cleared.
	HasMore bool         // if true an other call to delta should be made.
	Cursor  string       // Tag of the current state.
	Entries []DeltaEntry // List of changed entries.
}

// Changed entry.
type DeltaEntry struct {
	Path  string // Path of this entry in lowercase.
	Entry *Entry // nil when this entry does not exists.
}

// Reply of longpoll_delta.
type DeltaPoll struct {
	Changes bool `json:"changes"` // true if the polled path has changed.
	Backoff int  `json:"backoff"` // time in second before calling poll again.
}

// Reply of chunked_upload.
type ChunkUploadResponse struct {
	UploadId string `json:"upload_id"` // Unique ID of this upload.
	Offset   int    `json:"offset"`    // Size in bytes of already sent data.
	Expires  string `json:"expires"`   // Expiration time of this upload.
}

// Format of reply when http error code is not 200
// Format may be:
// {"error": "reason"}
// {"error": {"param": "reason"}}
type RequestError struct {
	Error interface{} `json:"error"` // Description of this error.
}

const (
	POLL_MIN_TIMEOUT        = 30                // Default number of entries returned by metadata.
	POLL_MAX_TIMEOUT        = 480               // Default number of entries returned by metadata.
	DEFAULT_CHUNK_SIZE      = 4 * 1024 * 1024   // Maximum size of a file sendable using files_put.
	MAX_PUT_FILE_SIZE       = 150 * 1024 * 1024 // Maximum size of a file sendable using files_put.
	METADATA_LIMIT_MAX      = 25000             // Maximum number of entries returned by metadata.
	METADATA_LIMIT_DEFAULT  = 10000             // Default number of entries returned by metadata.
	REVISIONS_LIMIT_MAX     = 1000              // Maximum number of revisions returned by revisions.
	REVISIONS_LIMIT_DEFAULT = 10                // Default number of revisions returned by revisions.
	SEARCH_LIMIT_MAX        = 1000              // Maximum number of entries returned by search.
	SEARCH_LIMIT_DEFAULT    = 1000              // Default number of entries returned by search.
	DATE_FORMAT             = time.RFC1123Z     // Format to use when decoding a time.
)

// A metadata entry that describes a file or folder.
type Entry struct {
	Bytes       int     `json:"bytes"`        // Size of the file in bytes.
	ClientMtime string  `json:"client_mtime"` // Modification time set by the client when added.
	Contents    []Entry `json:"contents"`     // List of children for a directory.
	Hash        string  `json:"hash"`         // hash of this entry.
	Icon        string  `json:"icon"`         // Name of the icon displayed for this entry.
	IsDeleted   bool    `json:"is_deleted"`   // true if this entry was deleted.
	IsDir       bool    `json:"is_dir"`       // true if this entry is a directory.
	MimeType    string  `json:"mime_type"`    // MimeType of this entry.
	Modified    string  `json:"modified"`     // Date of last modification.
	Path        string  `json:"path"`         // Absolute path of this entry.
	Revision    string  `json:"rev"`          // Unique ID for this file revision.
	Root        string  `json:"root"`         // dropbox or sandbox.
	Size        string  `json:"size"`         // Size of the file humanized/localized.
	ThumbExists bool    `json:"thumb_exists"` // true if a thumbnail is available for this entry.
}

// Link for sharing a file.
type Link struct {
	Expires string `json:"expires"` // Expiration date of this link.
	URL     string `json:"url"`     // URL to share.
}

// Dropbox client.
type Dropbox struct {
	RootDirectory string          // dropbox or sandbox.
	Locale        string          // Locale send to the API to translate/format messages.
	APIURL        string          // Normal API URL.
	APIContentURL string          // URL for transferring files.
	APINotifyURL  string          // URL for realtime notification.
	Session       oauth.Transport // OAuth 2.0 session.
}

// Return a new Dropbox configured.
func NewDropbox() *Dropbox {
	return &Dropbox{
		RootDirectory: "dropbox", // dropbox or sandbox.
		Locale:        "en",
		APIURL:        "https://api.dropbox.com/1",
		APIContentURL: "https://api-content.dropbox.com/1",
		APINotifyURL:  "https://api-notify.dropbox.com/1",
		Session: oauth.Transport{
			Config: &oauth.Config{
				AuthURL:  "https://www.dropbox.com/1/oauth2/authorize",
				TokenURL: "https://api.dropbox.com/1/oauth2/token",
			},
		},
	}
}

// Set the clientid (app_key), clientsecret (app_secret).
// You have to register an application on https://www.dropbox.com/developers/apps.
func (self *Dropbox) SetAppInfo(clientid, clientsecret string) {
	self.Session.Config.ClientId = clientid
	self.Session.Config.ClientSecret = clientsecret
}

// Set access token to avoid calling Auth method.
func (self *Dropbox) SetAccessToken(accesstoken string) {
	self.Session.Token = &oauth.Token{AccessToken: accesstoken}
}

// Get OAuth access token.
func (self *Dropbox) AccessToken() string {
	return self.Session.Token.AccessToken
}

// Display URL to authorize this application to connect to your account.
func (self *Dropbox) Auth() error {
	var code string

	fmt.Printf("Please visit:\n%s\nEnter the code: ",
		self.Session.Config.AuthCodeURL(""))
	fmt.Scanln(&code)
	_, err := self.Session.Exchange(code)
	return err
}

// End the chunked upload by giving a name to the UploadID.
func (self *Dropbox) CommitChunkedUpload(uploadid, dst string, overwrite bool, parentRev string) (*Entry, error) {
	var err error
	var rawurl string
	var response *http.Response
	var params *url.Values
	var body []byte
	var rv Entry

	if dst[0] == '/' {
		dst = dst[1:]
	}

	params = &url.Values{
		"locale":    {self.Locale},
		"upload_id": {uploadid},
		"overwrite": {strconv.FormatBool(overwrite)},
	}
	if len(parentRev) != 0 {
		params.Set("parent_rev", parentRev)
	}
	rawurl = fmt.Sprintf("%s/commit_chunked_upload/%s/%s?%s", self.APIContentURL, self.RootDirectory, dst, params.Encode())

	if response, err = self.Session.Client().Post(rawurl, "", nil); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if body, err = ioutil.ReadAll(response.Body); err == nil {
		err = json.Unmarshal(body, &rv)
	}
	return &rv, err
}

// Send a chunk with a maximum size of chunksize, if there is no session a new one is created.
func (self *Dropbox) ChunkedUpload(session *ChunkUploadResponse, input io.ReadCloser, chunksize int) (*ChunkUploadResponse, error) {
	var err error
	var rawurl string
	var cur ChunkUploadResponse
	var response *http.Response
	var body []byte
	var r *io.LimitedReader

	if chunksize <= 0 {
		chunksize = DEFAULT_CHUNK_SIZE
	} else if chunksize > MAX_PUT_FILE_SIZE {
		chunksize = MAX_PUT_FILE_SIZE
	}

	if session != nil {
		rawurl = fmt.Sprintf("%s/chunked_upload?upload_id=%s&offset=%d", self.APIContentURL, session.UploadId, session.Offset)
	} else {
		rawurl = fmt.Sprintf("%s/chunked_upload", self.APIContentURL)
	}
	r = &io.LimitedReader{R: input, N: int64(chunksize)}

	if response, err = self.Session.Client().Post(rawurl, "application/octet-stream", r); err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if r.N != 0 {
		return nil, io.EOF
	}

	if body, err = ioutil.ReadAll(response.Body); err == nil {
		err = json.Unmarshal(body, &cur)
	}
	return &cur, err
}

// Upload data from the input reader to the dst path on Dropbox by sending chunks of chunksize.
func (self *Dropbox) UploadByChunk(input io.ReadCloser, chunksize int, dst string, overwrite bool, parentRev string) (*Entry, error) {
	var err error
	var cur *ChunkUploadResponse
	var uploadId string

	if cur, err = self.ChunkedUpload(cur, input, chunksize); err != nil {
		return nil, err
	}
	uploadId = cur.UploadId
	for err == nil {
		if cur, err = self.ChunkedUpload(cur, input, chunksize); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return self.CommitChunkedUpload(uploadId, dst, overwrite, parentRev)
}

// Upload size bytes from the input reader to the dst path on Dropbox.
func (self *Dropbox) FilesPut(input io.ReadCloser, size int64, dst string, overwrite bool, parentRev string) (*Entry, error) {
	var err error
	var rawurl string
	var rv Entry
	var request *http.Request
	var response *http.Response
	var params *url.Values
	var body []byte

	if size > MAX_PUT_FILE_SIZE {
		return nil, fmt.Errorf("Could not upload files bigger than 150MB using this method, use UploadByChunk instead")
	}
	if dst[0] == '/' {
		dst = dst[1:]
	}

	params = &url.Values{"overwrite": {strconv.FormatBool(overwrite)}}
	if len(parentRev) != 0 {
		params.Set("parent_rev", parentRev)
	}
	rawurl = fmt.Sprintf("%s/files_put/%s/%s?%s", self.APIContentURL, self.RootDirectory, dst, params.Encode())

	if request, err = http.NewRequest("PUT", rawurl, input); err != nil {
		return nil, err
	}
	request.Header.Set("Content-Length", strconv.FormatInt(size, 10))
	if response, err = self.Session.Client().Do(request); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if body, err = ioutil.ReadAll(response.Body); err == nil {
		err = json.Unmarshal(body, &rv)
	}
	return &rv, err
}

// Upload the file located in the src path on the local disk to the dst path on Dropbox.
func (self *Dropbox) UploadFile(src, dst string, overwrite bool, parentRev string) (*Entry, error) {
	var err error
	var fd *os.File
	var fsize int64

	if fd, err = os.Open(src); err != nil {
		return nil, err
	}
	defer fd.Close()

	if fi, err := fd.Stat(); err == nil {
		fsize = fi.Size()
	} else {
		return nil, err
	}
	return self.FilesPut(fd, fsize, dst, overwrite, parentRev)
}

// Get a thumbnail for an image.
func (self *Dropbox) Thumbnails(src, format, size string) (io.ReadCloser, int64, *Entry, error) {
	var response *http.Response
	var rawurl string
	var err error
	var entry Entry

	switch format {
	case "":
		format = "jpeg"
	case "jpeg", "png":
		break
	default:
		return nil, 0, nil, fmt.Errorf("Unsupported format '%s' must be jpeg or png", format)
	}
	switch size {
	case "":
		size = "s"
	case "xs", "s", "m", "l", "xl":
		break
	default:
		return nil, 0, nil, fmt.Errorf("Unsupported size '%s' must be xs, s, m, l or xl", size)

	}
	if src[0] == '/' {
		src = src[1:]
	}
	rawurl = fmt.Sprintf("%s/thumbnails/%s/%s?format=%s&size=%s", self.APIContentURL, self.RootDirectory, src, format, size)
	if response, err = self.Session.Client().Get(rawurl); err != nil {
		return nil, 0, nil, err
	}
	switch response.StatusCode {
	case http.StatusNotFound:
		response.Body.Close()
		return nil, 0, nil, os.ErrNotExist
	case http.StatusUnsupportedMediaType:
		response.Body.Close()
		return nil, 0, nil, fmt.Errorf("The image located at '%s' cannot be converted to a thumbnail", src)
	}
	json.Unmarshal([]byte(response.Header.Get("x-dropbox-metadata")), &entry)
	return response.Body, response.ContentLength, &entry, err
}

// Download the file located in the src path on the Dropbox to the dst file on the local disk.
func (self *Dropbox) ThumbnailsToFile(src, dst, format, size string) (*Entry, error) {
	var input io.ReadCloser
	var fd *os.File
	var err error
	var entry *Entry

	if fd, err = os.Create(dst); err != nil {
		return nil, err
	}
	defer fd.Close()

	if input, _, entry, err = self.Thumbnails(src, format, size); err != nil {
		os.Remove(dst)
		return nil, err
	}
	defer input.Close()
	if _, err = io.Copy(fd, input); err != nil {
		os.Remove(dst)
	}
	return entry, err
}

// Request the file located at src, the specific revision may be given.
// offset is used in case the download was interrupted.
// A io.ReadCloser to get the file ans its size is returned.
func (self *Dropbox) Download(src, rev string, offset int) (io.ReadCloser, int64, error) {
	var request *http.Request
	var response *http.Response
	var rawurl string
	var err error

	if src[0] == '/' {
		src = src[1:]
	}

	rawurl = fmt.Sprintf("%s/files/%s/%s", self.APIContentURL, self.RootDirectory, src)
	if len(rev) != 0 {
		rawurl += fmt.Sprintf("?rev=%s", rev)
	}
	if request, err = http.NewRequest("GET", rawurl, nil); err != nil {
		return nil, 0, err
	}
	if offset != 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	if response, err = self.Session.Client().Do(request); err != nil {
		return nil, 0, err
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		return nil, 0, os.ErrNotExist
	}
	return response.Body, response.ContentLength, err
}

// Resume the download of the file located in the src path on the Dropbox to the dst file on the local disk.
func (self *Dropbox) DownloadToFileResume(src, dst, rev string) error {
	var input io.ReadCloser
	var fd *os.File
	var offset int
	var err error

	if fd, err = os.OpenFile(dst, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		return err
	}
	if fi, err := fd.Stat(); err != nil {
		return err
	} else {
		offset = int(fi.Size())
	}
	defer fd.Close()

	if input, _, err = self.Download(src, rev, offset); err != nil {
		return err
	}
	defer input.Close()
	_, err = io.Copy(fd, input)
	return err
}

// Download the file located in the src path on the Dropbox to the dst file on the local disk.
// If the destination file exists it will be truncated.
func (self *Dropbox) DownloadToFile(src, dst, rev string) error {
	var input io.ReadCloser
	var fd *os.File
	var err error

	if fd, err = os.Create(dst); err != nil {
		return err
	}
	defer fd.Close()

	if input, _, err = self.Download(src, rev, 0); err != nil {
		os.Remove(dst)
		return err
	}
	defer input.Close()
	if _, err = io.Copy(fd, input); err != nil {
		os.Remove(dst)
	}
	return err
}

func (self *Dropbox) doRequest(method, path string, params *url.Values, receiver interface{}) error {
	var body []byte
	var rawurl string
	var response *http.Response
	var request *http.Request
	var err error

	if params == nil {
		params = &url.Values{"locale": {self.Locale}}
	}
	rawurl = fmt.Sprintf("%s/%s?%s", self.APIURL, path, params.Encode())
	if request, err = http.NewRequest(method, rawurl, nil); err != nil {
		return err
	}
	if response, err = self.Session.Client().Do(request); err != nil {
		return err
	}
	defer response.Body.Close()
	if body, err = ioutil.ReadAll(response.Body); err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusNotFound:
		return os.ErrNotExist
	case http.StatusBadRequest, http.StatusMethodNotAllowed:
		var reqerr RequestError
		if err = json.Unmarshal(body, &reqerr); err != nil {
			return err
		}
		switch v := reqerr.Error.(type) {
		case string:
			return fmt.Errorf("%s", v)
		case map[string]interface{}:
			for param, reason := range v {
				if reasonstr, ok := reason.(string); ok {
					return fmt.Errorf("%s: %s", param, reasonstr)
				}
			}
			return fmt.Errorf("Wrong parameter")
		default:
			return fmt.Errorf("Request error HTTP code %d", response.StatusCode)
		}
	case http.StatusUnauthorized:
		return ErrNotAuth
	}
	err = json.Unmarshal(body, receiver)
	return err
}

// Get account information for the user currently authenticated.
func (self *Dropbox) GetAccountInfo() (*Account, error) {
	var rv Account

	err := self.doRequest("GET", "account/info", nil, &rv)
	return &rv, err
}

// Share a file.
func (self *Dropbox) Shares(path string, shortUrl bool) (*Link, error) {
	var rv Link
	var params *url.Values

	if shortUrl {
		params = &url.Values{"short_url": {strconv.FormatBool(shortUrl)}}
	}
	act := strings.Join([]string{"shares", self.RootDirectory, path}, "/")
	err := self.doRequest("POST", act, params, &rv)
	return &rv, err
}

// Share a file for streaming.
func (self *Dropbox) Media(path string) (*Link, error) {
	var rv Link

	act := strings.Join([]string{"media", self.RootDirectory, path}, "/")
	err := self.doRequest("POST", act, nil, &rv)
	return &rv, err
}

// Search entries matching all the words contained in query contained in path.
// The maximum number of entries and whether to consider deleted file may be given.
func (self *Dropbox) Search(path, query string, fileLimit int, includeDeleted bool) (*[]Entry, error) {
	var rv []Entry
	var params *url.Values

	if fileLimit <= 0 || fileLimit > SEARCH_LIMIT_MAX {
		fileLimit = SEARCH_LIMIT_DEFAULT
	}
	params = &url.Values{
		"query":           {query},
		"file_limit":      {strconv.FormatInt(int64(fileLimit), 10)},
		"include_deleted": {strconv.FormatBool(includeDeleted)},
	}
	act := strings.Join([]string{"search", self.RootDirectory, path}, "/")
	err := self.doRequest("GET", act, params, &rv)
	return &rv, err
}

// Get modifications since the cursor.
func (self *Dropbox) Delta(cursor, pathPrefix string) (*DeltaPage, error) {
	var rv DeltaPage
	var params *url.Values
	type deltaPageParser struct {
		Reset   bool                `json:"reset"`    // if true the local state must be cleared.
		HasMore bool                `json:"has_more"` // if true an other call to delta should be made.
		Cursor  string              `json:"cursor"`   // Tag of the current state.
		Entries [][]json.RawMessage `json:"entries"`  // List of changed entries.
	}
	var dpp deltaPageParser

	params = &url.Values{}
	if len(cursor) != 0 {
		params.Set("cursor", cursor)
	}
	if len(pathPrefix) != 0 {
		params.Set("path_prefix", pathPrefix)
	}
	err := self.doRequest("POST", "delta", params, &dpp)
	rv = DeltaPage{Reset: dpp.Reset, HasMore: dpp.HasMore, Cursor: dpp.Cursor}
	rv.Entries = make([]DeltaEntry, 0, len(dpp.Entries))
	for _, jentry := range dpp.Entries {
		var path string
		var entry Entry

		if len(jentry) != 2 {
			return nil, fmt.Errorf("Malformed reply")
		}

		if err = json.Unmarshal(jentry[0], &path); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(jentry[1], &entry); err != nil {
			return nil, err
		}
		if entry.Path == "" {
			rv.Entries = append(rv.Entries, DeltaEntry{Path: path, Entry: nil})
		} else {
			rv.Entries = append(rv.Entries, DeltaEntry{Path: path, Entry: &entry})
		}
	}
	return &rv, err
}

// Wait for a notification to happen.
func (self *Dropbox) LongPollDelta(cursor string, timeout int) (*DeltaPoll, error) {
	var rv DeltaPoll
	var params *url.Values
	var body []byte
	var rawurl string
	var response *http.Response
	var err error
	var client http.Client

	params = &url.Values{}
	if timeout != 0 {
		if timeout < POLL_MIN_TIMEOUT || timeout > POLL_MAX_TIMEOUT {
			return nil, fmt.Errorf("Timeout out of range [%d; %d]", POLL_MIN_TIMEOUT, POLL_MAX_TIMEOUT)
		}
		params.Set("timeout", strconv.FormatInt(int64(timeout), 10))
	}
	params.Set("cursor", cursor)
	rawurl = fmt.Sprintf("%s/longpoll_delta?%s", self.APINotifyURL, params.Encode())
	if response, err = client.Get(rawurl); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if body, err = ioutil.ReadAll(response.Body); err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusBadRequest {
		var reqerr RequestError
		if err = json.Unmarshal(body, &reqerr); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s", reqerr.Error)
	}
	err = json.Unmarshal(body, &rv)
	return &rv, err
}

// Get metadata for a file or a directory.
// If list is true and src is a directory, immediate child will be sent in the Contents field.
// If include_deleted is true, entries deleted will be sent.
// hash is the hash of the contents of a directory, it is used to avoid sending data when directory did not change.
// rev is the specific revision to get the metadata from.
// limit is the maximum number of entries requested.
func (self *Dropbox) Metadata(src string, list bool, includeDeleted bool, hash, rev string, limit int) (*Entry, error) {
	var rv Entry
	var params *url.Values

	if limit <= 0 {
		limit = METADATA_LIMIT_DEFAULT
	} else if limit > METADATA_LIMIT_MAX {
		limit = METADATA_LIMIT_MAX
	}
	params = &url.Values{
		"list":            {strconv.FormatBool(list)},
		"include_deleted": {strconv.FormatBool(includeDeleted)},
		"file_limit":      {strconv.FormatInt(int64(limit), 10)},
	}
	if len(rev) != 0 {
		params.Set("rev", rev)
	}
	if len(hash) != 0 {
		params.Set("hash", hash)
	}

	act := strings.Join([]string{"metadata", self.RootDirectory, src}, "/")
	err := self.doRequest("GET", act, params, &rv)
	return &rv, err
}

// Get a reference to a file.
// This reference can be used to copy this file to another user's Dropbox by passing it to the Copy method.
func (self *Dropbox) CopyRef(src string) (*CopyRef, error) {
	var rv CopyRef
	act := strings.Join([]string{"copy_ref", self.RootDirectory, src}, "/")
	err := self.doRequest("GET", act, nil, &rv)
	return &rv, err
}

// Get a list of revisions for a file.
func (self *Dropbox) Revisions(src string, revLimit int) (*[]Entry, error) {
	var rv []Entry
	if revLimit <= 0 {
		revLimit = REVISIONS_LIMIT_DEFAULT
	} else if revLimit > REVISIONS_LIMIT_MAX {
		revLimit = REVISIONS_LIMIT_MAX
	}
	act := strings.Join([]string{"revisions", self.RootDirectory, src}, "/")
	err := self.doRequest("GET", act,
		&url.Values{"rev_limit": {strconv.FormatInt(int64(revLimit), 10)}}, &rv)
	return &rv, err
}

// Restore a deleted file at the corresponding revision.
func (self *Dropbox) Restore(src string, rev string) (*Entry, error) {
	var rv Entry
	act := strings.Join([]string{"restore", self.RootDirectory, src}, "/")
	err := self.doRequest("POST", act, &url.Values{"rev": {rev}}, &rv)
	return &rv, err
}

// Copy a file.
// If isRef is true src must be a reference from CopyRef instead of a path.
func (self *Dropbox) Copy(src, dst string, isRef bool) (*Entry, error) {
	var rv Entry
	params := &url.Values{"root": {self.RootDirectory}, "to_path": {dst}}
	if isRef {
		params.Set("from_path", src)
	} else {
		params.Set("from_copy_ref", src)
	}
	err := self.doRequest("POST", "fileops/copy", params, &rv)
	return &rv, err
}

// Create a new directory.
func (self *Dropbox) CreateFolder(path string) (*Entry, error) {
	var rv Entry
	err := self.doRequest("POST", "fileops/create_folder",
		&url.Values{"root": {self.RootDirectory}, "path": {path}}, &rv)
	return &rv, err
}

// Remove a file or directory (it is a recursive delete).
func (self *Dropbox) Delete(path string) (*Entry, error) {
	var rv Entry
	err := self.doRequest("POST", "fileops/delete",
		&url.Values{"root": {self.RootDirectory}, "path": {path}}, &rv)
	return &rv, err
}

// Move a file or directory.
func (self *Dropbox) Move(src, dst string) (*Entry, error) {
	var rv Entry
	err := self.doRequest("POST", "fileops/move",
		&url.Values{"root": {self.RootDirectory},
			"from_path": {src},
			"to_path":   {dst}}, &rv)
	return &rv, err
}
