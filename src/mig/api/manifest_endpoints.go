// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Aaron Meihm ameihm@mozilla.com [:alm]
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
	"os"
	"path"
)

// API entry point used to request a file be sent to the loader from the API.
func getManifestFile(respWriter http.ResponseWriter, request *http.Request) {
	loc := fmt.Sprintf("%s%s", ctx.Server.Host, request.URL.String())
	opid := getOpID(request)
	resource := cljs.New(loc)
	defer func() {
		if e := recover(); e != nil {
			ctx.Channels.Log <- mig.Log{OpID: opid, Desc: fmt.Sprintf("%v", e)}.Err()
			resource.SetError(cljs.Error{Code: fmt.Sprintf("%.0f", opid), Message: fmt.Sprintf("%v", e)})
			respond(500, resource, respWriter, request)
		}
		ctx.Channels.Log <- mig.Log{OpID: opid, Desc: "leaving getManifestFile()"}.Debug()
	}()
	err := request.ParseMultipartForm(20480)
	if err != nil {
		panic(err)
	}

	ctx.Channels.Log <- mig.Log{OpID: opid, Desc: fmt.Sprintf("Received manifest file request")}.Debug()

	var manifestParam mig.ManifestParameters
	err = json.Unmarshal([]byte(request.FormValue("parameters")), &manifestParam)
	if err != nil {
		panic(err)
	}
	err = manifestParam.ValidateFetch()
	if err != nil {
		panic(err)
	}

	root, manifest, err := manifestRoot(manifestParam)
	if err != nil {
		panic(err)
	}

	// Validate the object being requested exists in the manifest.
	var mentry *mig.ManifestEntry
	for i := range manifest.Entries {
		if manifest.Entries[i].Name == manifestParam.Object {
			mentry = &manifest.Entries[i]
			break
		}
	}
	if mentry == nil {
		panic("requested object does not exist in manifest")
	}

	filepath := path.Join(root, "files", mentry.Name)
	buf, err := loadContent(filepath, mentry.SHA256)
	if err != nil {
		panic(err)
	}

	fetchresp := mig.ManifestFetchResponse{}
	fetchresp.Data = buf
	err = resource.AddItem(cljs.Item{
		Href: request.URL.String(),
		Data: []cljs.Data{
			{
				Name:  "content",
				Value: fetchresp,
			},
		}})
	if err != nil {
		panic(err)
	}
	respond(200, resource, respWriter, request)
}

// Load the file from the file system, we also compress it and return a byte
// slice. Validate the SHA256 sum of the file against the sum that was
// specified in the manifest to ensure we are sending the correct data.
func loadContent(path string, sig string) ([]byte, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load manifest object")
	}

	h := sha256.New()
	b := new(bytes.Buffer)
	gz := gzip.NewWriter(b)
	buf := make([]byte, 4096)
	for {
		n, err := fd.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fd.Close()
			gz.Close()
			return nil, err
		}
		if n > 0 {
			h.Write(buf[:n])
			_, err = gz.Write(buf[:n])
			if err != nil {
				fd.Close()
				gz.Close()
				return nil, err
			}
		}
	}
	fd.Close()
	gz.Close()
	vsig := fmt.Sprintf("%x", h.Sum(nil))
	if vsig != sig {
		return nil, fmt.Errorf("manifest signature did not match file")
	}

	return b.Bytes(), nil
}

// This API entry point is used by the loader to request a manifest file that
// indicates the most current version of the agent to be used. The loader
// sends some basic information in the request parameters so the API can decide
// which manifest to send the loader.
func getAgentManifest(respWriter http.ResponseWriter, request *http.Request) {
	loc := fmt.Sprintf("%s%s", ctx.Server.Host, request.URL.String())
	opid := getOpID(request)
	resource := cljs.New(loc)
	defer func() {
		if e := recover(); e != nil {
			ctx.Channels.Log <- mig.Log{OpID: opid, Desc: fmt.Sprintf("%v", e)}.Err()
			resource.SetError(cljs.Error{Code: fmt.Sprintf("%.0f", opid), Message: fmt.Sprintf("%v", e)})
			respond(500, resource, respWriter, request)
		}
		ctx.Channels.Log <- mig.Log{OpID: opid, Desc: "leaving getAgentManifest()"}.Debug()
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
	ctx.Channels.Log <- mig.Log{OpID: opid, Desc: fmt.Sprintf("Received manifest request")}.Debug()

	_, m, err := manifestRoot(manifestParam)
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

func manifestRoot(p mig.ManifestParameters) (string, mig.ManifestResponse, error) {
	// Construct the path to the manifest using the parameters supplied by
	// the client. These should be validated to be safe via
	// ManifestParameters.Validate().
	proot := path.Join(ctx.Manifest.Path, p.Operator, p.Arch, p.OS)
	psecondary := path.Join(ctx.Manifest.Path, "default", p.Arch, p.OS)
	primary := path.Join(proot, "manifest.json")
	secondary := path.Join(psecondary, "manifest.json")
	m, err := manifestLoad(primary)
	if err == nil {
		return proot, m, nil
	}
	m, err = manifestLoad(secondary)
	if err == nil {
		return psecondary, m, nil
	}
	return "", mig.ManifestResponse{}, fmt.Errorf("unable to locate manifest")
}
