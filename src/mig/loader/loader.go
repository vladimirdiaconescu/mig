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
	"fmt"
	"mig"
	"os"
	"runtime"
)

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

func main() {
	runtime.GOMAXPROCS(1)

	// Get our current status from the file system.
	_, err := initializeHaveBundle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "main() -> %v\n", err)
		os.Exit(1)
	}

	// Retrieve our manifest from the API.
}
