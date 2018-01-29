/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package compatibility

import (
	"github.com/xlab-si/emmy/client"
)

// ServiceInfo holds information about the secure service provider and its service offering.
type ServiceInfo struct {
	Name        string
	Description string
	Provider    string
}

// GetServiceInfo contacts emmy server to retrieve basic information about its secure service
// offering.
func GetServiceInfo(conn *Connection) (*ServiceInfo, error) {
	serviceInfo, err := client.GetServiceInfo(conn.ClientConn)
	if err != nil {
		return nil, err
	}

	return &ServiceInfo{
		Name:        serviceInfo.Name,
		Description: serviceInfo.Description,
		Provider:    serviceInfo.Provider,
	}, nil
}
