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

package client

import (
	"fmt"
	pb "github.com/xlab-si/emmy/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// ServiceInfo holds the data related to the service supported by emmy.
// All fields are exported to ensure access to data from any package.
type ServiceInfo struct {
	Name        string
	Description string
	Provider    string
}

// NewServiceInfo accepts the matching *pb.ServiceInfo type and returns a pointer to our own
// ServiceInfo type.
func NewServiceInfo(info *pb.ServiceInfo) *ServiceInfo {
	return &ServiceInfo{
		Name:        info.GetName(),
		Description: info.GetDescription(),
		Provider:    info.GetProvider(),
	}
}

func GetServiceInfo(conn *grpc.ClientConn) (*ServiceInfo, error) {
	logger.Debug("GetServiceInfo invoked")
	client := pb.NewInfoClient(conn)

	info, err := client.GetServiceInfo(context.Background(), &pb.EmptyMsg{})
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve service info: %v", err)
	}

	serviceInfo := NewServiceInfo(info)
	logger.Noticef("Retrieved service info:\n Name: %s\n Provider: %s\n Description: %s",
		serviceInfo.Name, serviceInfo.Provider, serviceInfo.Description)

	return serviceInfo, nil
}
