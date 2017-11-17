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
	"github.com/xlab-si/emmy/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func GetServiceInfo(conn *grpc.ClientConn) (*types.ServiceInfo, error) {
	logger.Debug("GetServiceInfo invoked")
	client := pb.NewInfoClient(conn)

	info, err := client.GetServiceInfo(context.Background(), &pb.EmptyMsg{})
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve service info: %v", err)
	}

	serviceInfo := types.NewServiceInfo(info.GetName(), info.GetDescription(), info.GetProvider())
	logger.Noticef("Retrieved service info:\n Name: %s\n Provider: %s\n Description: %s",
		serviceInfo.Name, serviceInfo.Provider, serviceInfo.Description)

	return serviceInfo, nil
}
