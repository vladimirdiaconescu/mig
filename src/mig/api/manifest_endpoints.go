// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Aaron Meihm ameihm@mozilla.com [:alm]
package main

import (
	"encoding/json"
	"fmt"
	"github.com/jvehent/cljs"
	"io/ioutil"
	"mig"
	"net/http"
	"os"
	"path"
)

// This API entry point is used by the loader to request a manifest file that
// indicates the most current version of the agent to be used.
func getAgentManifest(respWriter http.ResponseWriter, request *http.Request) {
	loc := fmt.Sprintf("%s%s", ctx.Server.Host, request.URL.String())
	opid := getOpID(request)
	resource := cljs.New(loc)
	defer func() {
		if e := recover(); e != nil {
			ctx.Channels.Log <- mig.Log{Desc: fmt.Sprintf("%v", e)}.Err()
			resource.SetError(cljs.Error{Code: fmt.Sprintf("%.0f", opid), Message: fmt.Sprintf("%v", e)})
			respond(500, resource, respWriter, request)
		}
		ctx.Channels.Log <- mig.Log{Desc: "leaving getAgentManifest()"}.Debug()
	}()
	err := request.ParseMultipartForm(20480)
	if err != nil {
		panic(err)
	}

	var manifestParam mig.ManifestParameters
	err = json.Unmarshal([]byte(request.FormValue("parameters")), &manifestParam)
	if err != nil {
		panic(err)
	}
	err = manifestParam.Validate()
	if err != nil {
		panic(err)
	}
	ctx.Channels.Log <- mig.Log{Desc: fmt.Sprintf("Received manifest request")}.Debug()

	m, err := getManifestResponse(manifestParam)
	if err != nil {
		panic(err)
	}
	err = resource.AddItem(cljs.Item{
		Href: request.URL.String(),
		Data: []cljs.Data{
			{
				Name:  "manifest",
				Value: m,
			},
		}})
	if err != nil {
		panic(err)
	}
	respond(200, resource, respWriter, request)
}

func manifestLoad(path string) (mig.ManifestResponse, error) {
	ret := mig.ManifestResponse{}
	fd, err := os.Open(path)
	if err != nil {
		return ret, err
	}
	defer fd.Close()
	buf, err := ioutil.ReadAll(fd)
	if err != nil {
		return ret, err
	}
	err = json.Unmarshal(buf, &ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func getManifestResponse(p mig.ManifestParameters) (mig.ManifestResponse, error) {
	ret := mig.ManifestResponse{}
	// Construct the path to the manifest using the parameters supplied by
	// the client. These should be validated to be safe via
	// ManifestParameters.Validate().
	primary := path.Join(ctx.Manifest.Path, p.Operator, p.Arch, p.OS, "manifest.json")
	secondary := path.Join(ctx.Manifest.Path, "default", p.Arch, p.OS, "manifest.json")
	ctx.Channels.Log <- mig.Log{Desc: fmt.Sprintf("Primary: %v", primary)}.Debug()
	ctx.Channels.Log <- mig.Log{Desc: fmt.Sprintf("Secondary: %v", secondary)}.Debug()

	m, err := manifestLoad(primary)
	if err != nil {
		// Try to load the secondary manifest, if this doesn't work
		// either give up.
		m, err = manifestLoad(secondary)
		if err != nil {
			return ret, fmt.Errorf("unable to locate manifest")
		}
	}
	return m, nil
}
