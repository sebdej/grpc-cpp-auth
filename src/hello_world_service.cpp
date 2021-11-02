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

#include "hello_world_service.h"

#include <spdlog/spdlog.h>

#include <chrono>

#include "server_reactor.h"

HelloWorldService::HelloWorldService(std::string_view signingKey)
    : m_signingKey(signingKey) {
}

class LoginReactor: public AuthenticatedServerUnaryReactorT<hello_world::LoginRequest, hello_world::LoginResponse> {
 public:
  LoginReactor(std::string const& signingKey, hello_world::LoginRequest const* request, hello_world::LoginResponse* response)
      : AuthenticatedServerUnaryReactorT(signingKey, request, response) {
    if (request->username() == "admin" && request->password() == "abcde") {
      CreateAuthenticationToken("admin", {"user", "admin"});
    } else {
      Finish(Unauthenticated());
    }
  }

 private:
  void CreateAuthenticationToken(std::string const& username, std::initializer_list<std::string> const& roles) {
    auto authenticationToken = new hello_world::AuthenticationToken();
    auto expires = std::chrono::utc_clock::now() + std::chrono::minutes(60);

    authenticationToken->set_expires(expires.time_since_epoch().count());
    authenticationToken->set_username(username);

    for (auto const& role : roles) {
      authenticationToken->add_roles(role);
    }

    m_response->set_auth_token(CreateSignedAuthenticationToken(authenticationToken));

    Finish(grpc::Status::OK);
  }
};

grpc::ServerUnaryReactor* HelloWorldService::Login(grpc::CallbackServerContext* context, hello_world::LoginRequest const* request,
                                                   hello_world::LoginResponse* response) {
  return new LoginReactor(m_signingKey, request, response);
}

class HelloWorldReactor: public AuthenticatedServerUnaryReactorT<hello_world::HelloWorldRequest, hello_world::HelloWorldResponse> {
 public:
  HelloWorldReactor(std::string const& signingKey, grpc::CallbackServerContext* context, hello_world::HelloWorldRequest const* request,
                    hello_world::HelloWorldResponse* response)
      : AuthenticatedServerUnaryReactorT(signingKey, request, response) {
    if (auto authToken = GetAuthorizationTokenOrFinish(context)) {
      response->set_message(fmt::format("[username: {}] Hello {}!", authToken->username(), request->name()));

      Finish(grpc::Status::OK);
    }
  }
};

grpc::ServerUnaryReactor* HelloWorldService::HelloWorld(grpc::CallbackServerContext* context, hello_world::HelloWorldRequest const* request,
                                                        hello_world::HelloWorldResponse* response) {
  return new HelloWorldReactor(m_signingKey, context, request, response);
}