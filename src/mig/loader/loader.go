// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Aaron Meihm ameihm@mozilla.com [:alm]

// The MIG loader is a simple bootstrapping tool for MIG. It can be scheduled
// to run on a host system and download the newest available version of the
// agent. If the loader identifies a newer version of the agent available, it
// will download the required files from the API, replace the existing files,
// and notify any existing agent it should terminate.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/jvehent/cljs"
	"io"
	"io/ioutil"
	"mig"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
)

var apiManifest *mig.ManifestResponse

func initializeHaveBundle() ([]mig.BundleDictionaryEntry, error) {
	ret, err := mig.GetHostBundle()
	if err != nil {
		return nil, err
	}
	ret, err = mig.HashBundle(ret)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "initializeHaveBundle() -> Initialized\n")
	for _, x := range ret {
		fmt.Fprintf(os.Stderr, "%v %v -> %v\n", x.Name, x.Path, x.SHA256)
	}
	return ret, nil
}

func requestManifest() error {
	murl := APIURL + "manifest"
	fmt.Fprintf(os.Stderr, "requestManifest() -> requesting manifest from %v\n", murl)

	mparam := mig.ManifestParameters{}
	mparam.OS = runtime.GOOS
	mparam.Arch = runtime.GOARCH
	if TAGS.Operator == "" {
		mparam.Operator = "default"
	} else {
		mparam.Operator = TAGS.Operator
	}
	buf, err := json.Marshal(mparam)
	if err != nil {
		return err
	}
	mstring := string(buf)
	data := url.Values{"parameters": {mstring}}
	r, err := http.NewRequest("POST", murl, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var resource *cljs.Resource
	err = json.Unmarshal(body, &resource)
	if err != nil {
		return err
	}

	// Extract our manifest from the response.
	manifest, err := valueToManifest(resource.Collection.Items[0].Data[0].Value)
	if err != nil {
		return err
	}
	apiManifest = &manifest

	return nil
}

func valueToManifest(v interface{}) (m mig.ManifestResponse, err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	err = json.Unmarshal(b, &m)
	return
}

func valueToFetchResponse(v interface{}) (m mig.ManifestFetchResponse, err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	err = json.Unmarshal(b, &m)
	return
}

func fetchFile(n string) ([]byte, error) {
	murl := APIURL + "manifest/fetch"

	mparam := mig.ManifestParameters{}
	mparam.OS = runtime.GOOS
	mparam.Arch = runtime.GOARCH
	mparam.Operator = TAGS.Operator
	mparam.Object = n
	buf, err := json.Marshal(mparam)
	if err != nil {
		return nil, err
	}
	mstring := string(buf)
	data := url.Values{"parameters": {mstring}}
	r, err := http.NewRequest("POST", murl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var resource *cljs.Resource
	err = json.Unmarshal(body, &resource)
	if err != nil {
		return nil, err
	}

	// Extract fetch response.
	fetchresp, err := valueToFetchResponse(resource.Collection.Items[0].Data[0].Value)
	if err != nil {
		return nil, err
	}

	// Decompress the returned file and return it as a byte slice.
	b := bytes.NewBuffer(fetchresp.Data)
	gz, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}
	ret, err := ioutil.ReadAll(gz)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func fetchAndReplace(entry mig.BundleDictionaryEntry, sig string) error {
	// Grab the new file from the API.
	filebuf, err := fetchFile(entry.Name)
	if err != nil {
		return err
	}

	// Stage the new file. Write the file recieved from the API to the
	// file system and validate the signature of the new file to make
	// sure it matches the signature from the manifest.
	//
	// Append .loader to the file name to use as the staged file path.
	reppath := entry.Path + ".loader"
	fd, err := os.OpenFile(reppath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, err = fd.Write(filebuf)
	if err != nil {
		return err
	}
	fd.Close()

	// Validate the signature on the new file.
	h := sha256.New()
	fd, err = os.Open(reppath)
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := fd.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fd.Close()
			return err
		}
		if n > 0 {
			h.Write(buf[:n])
		}
	}
	fd.Close()
	if sig != fmt.Sprintf("%x", h.Sum(nil)) {
		return fmt.Errorf("staged file signature mismatch")
	}

	// Got this far, OK to proceed with the replacement.
	err = os.Rename(reppath, entry.Path)

	return nil
}

func checkEntry(entry mig.BundleDictionaryEntry) error {
	var compare mig.ManifestEntry
	fmt.Fprintf(os.Stderr, "checkEntry() -> Comparing %v %v\n", entry.Name, entry.Path)
	found := false
	for _, x := range apiManifest.Entries {
		if x.Name == entry.Name {
			compare = x
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "checkEntry() -> entry not in manifest, ignoring\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "checkEntry() -> We have %v\n", entry.SHA256)
	fmt.Fprintf(os.Stderr, "checkEntry() -> API has %v\n", compare.SHA256)
	if entry.SHA256 == compare.SHA256 {
		fmt.Fprintf(os.Stderr, "checkEntry() -> Nothing to do here...\n")
		//return nil
	}
	fmt.Fprintf(os.Stderr, "checkEntry() -> refreshing %v\n", entry.Name)
	err := fetchAndReplace(entry, compare.SHA256)
	if err != nil {
		return err
	}
	return nil
}

// Compare the manifest that the API sent with our knowledge of what is
// currently installed. For each case there is a difference, we will
// request the new file and replace the existing entry.
func compareManifest(have []mig.BundleDictionaryEntry) error {
	for _, x := range have {
		err := checkEntry(x)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	runtime.GOMAXPROCS(1)

	// Get our current status from the file system.
	have, err := initializeHaveBundle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "main() -> %v\n", err)
		os.Exit(1)
	}

	// Retrieve our manifest from the API.
	err = requestManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "main() -> %v\n", err)
		os.Exit(1)
	}

	err = compareManifest(have)
	if err != nil {
		fmt.Fprintf(os.Stderr, "main() -> %v\n", err)
		os.Exit(1)
	}
}
