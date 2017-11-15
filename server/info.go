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

package server

import (
	"github.com/xlab-si/emmy/config"
	pb "github.com/xlab-si/emmy/protobuf"
	"golang.org/x/net/context"
)

func (s *Server) GetServiceInfo(ctx context.Context, message *pb.EmptyMsg) (*pb.ServiceInfo, error) {
	s.logger.Info("Client requested service information")

	serviceInfo := config.LoadServiceInfo()
	info := &pb.ServiceInfo{
		Name:        serviceInfo.Name,
		Provider:    serviceInfo.Provider,
		Description: serviceInfo.Description,
	}

	return info, nil
}
