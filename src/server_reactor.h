//  Copyright 2021 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#ifndef _SERVER_REACTOR_H_
#define _SERVER_REACTOR_H_

#include <grpcpp/grpcpp.h>
#include <hello_world.grpc.pb.h>

#include <memory>
#include <string>
#include <string_view>

class AuthenticatedServerUnaryReactor: public grpc::ServerUnaryReactor {
 public:
  void OnDone() override;
  void OnCancel() override;

 protected:
  AuthenticatedServerUnaryReactor(std::string const& signingKey);

  grpc::Status Unauthenticated(std::string const& message = "Unauthenticated");

  grpc::Status InternalError(std::string const& message = "Internal error");

  std::string CreateSignedAuthenticationToken(hello_world::AuthenticationToken const* authenticationToken);

  std::shared_ptr<hello_world::AuthenticationToken> ParseAuthenticationToken(std::string_view value);

  std::shared_ptr<hello_world::AuthenticationToken> GetAuthorizationToken(grpc::CallbackServerContext* context);

  std::shared_ptr<hello_world::AuthenticationToken> GetAuthorizationTokenOrFinish(grpc::CallbackServerContext* context);

 private:
  std::string const& m_signingKey;
};

template <class REQUEST, class RESPONSE>
class AuthenticatedServerUnaryReactorT: public AuthenticatedServerUnaryReactor {
 protected:
  REQUEST const* const m_request;
  RESPONSE* const m_response;

  AuthenticatedServerUnaryReactorT(std::string const& signingKey, REQUEST const* request, RESPONSE* response)
      : AuthenticatedServerUnaryReactor(signingKey)
      , m_request(request)
      , m_response(response) {
  }
};

#endif