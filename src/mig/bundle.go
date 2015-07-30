// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Aaron Meihm ameihm@mozilla.com [:alm]
package mig

// This file contains structures and functions related to the handling of
// manifests and state bundles by the MIG loader and API.

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
)

// Manifest parameters are sent from the loader to the API as part of
// a manifest request.
type ManifestParameters struct {
	Operator string `json:"operator"` // Agent operator
	OS       string `json:"os"`       // Operating system
	Arch     string `json:"arch"`     // Architecture
}

func (m *ManifestParameters) Validate() error {
	if m.Operator == "" || m.OS == "" || m.Arch == "" {
		return fmt.Errorf("invalid manifest parameters")
	}

	// Since we use these to construct a path to the manifest file, make
	// sure we have what we expect.
	pre := regexp.MustCompile("^[A-Za-z0-9]+$")
	if !pre.MatchString(m.Operator) || !pre.MatchString(m.OS) || !pre.MatchString(m.Arch) {
		return fmt.Errorf("bad characters in manifest parameters")
	}

	return nil
}

type ManifestResponse struct {
	Entries []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Name   string `json:"name"`   // Corresponds to a bundle name
	SHA256 string `json:"sha256"` // SHA256 of entry
}

// The bundle dictionary is used to map tokens within the loader manifest to
// objects on the file system. We don't allow specification of an exact path
// for interrogation or manipulation in the manifest. This results in some
// restrictions but hardens the loader against making unauthorized changes
// to the file system.
type BundleDictionaryEntry struct {
	Name   string
	Path   string
	SHA256 string
}

var bundleEntryLinux = []BundleDictionaryEntry{
	{"agent", "/sbin/mig-agent", ""},
	{"configuration", "/etc/mig/mig-agent.cfg", ""},
}

var BundleDictionary = map[string][]BundleDictionaryEntry{
	"linux": bundleEntryLinux,
}

func GetHostBundle() ([]BundleDictionaryEntry, error) {
	switch runtime.GOOS {
	case "linux":
		return bundleEntryLinux, nil
	}
	return nil, fmt.Errorf("GetHostBundle() -> no entry for %v in bundle dictionary", runtime.GOOS)
}

func HashBundle(b []BundleDictionaryEntry) ([]BundleDictionaryEntry, error) {
	ret := b
	for i := range ret {
		fd, err := os.Open(ret[i].Path)
		if err != nil {
			// If the file does not exist we don't treat this as as
			// an error. This is likely in cases with embedded
			// configurations. In this case we leave the SHA256 as
			// an empty string.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		h := sha256.New()
		buf := make([]byte, 4096)
		for {
			n, err := fd.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				fd.Close()
				return nil, err
			}
			if n > 0 {
				h.Write(buf[:n])
			}
		}
		fd.Close()
		ret[i].SHA256 = fmt.Sprintf("%x", h.Sum(nil))
	}
	return ret, nil
}
