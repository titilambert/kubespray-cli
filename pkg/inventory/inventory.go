// Copyright © 2016 Smana <smainklh@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inventory

import (
	"fmt"
	"net"

	"github.com/nu7hatch/gouuid"
)

type ansibleHost struct {
	Hostname   string
	SSHAddress net.IP
}

type KargoInventory struct {
	etcds   []string
	masters []string
	nodes   []string
}

func ReadInventory(path string) []string {
	clusterName, err := uuid.NewV4().String()
	fmt.Println("do something")
	return clusterName
}