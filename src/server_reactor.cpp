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

#include "server_reactor.h"

#include <spdlog/spdlog.h>

#include <chrono>
#include <sstream>

#include "utilities.h"

void AuthenticatedServerUnaryReactor::OnDone() {
  spdlog::info("AuthenticatedServerUnaryReactor::OnDone");
}

void AuthenticatedServerUnaryReactor::OnCancel() {
  spdlog::info("AuthenticatedServerUnaryReactor::OnCancel");
}

AuthenticatedServerUnaryReactor::AuthenticatedServerUnaryReactor(std::string const& signingKey)
    : m_signingKey(signingKey) {
}

grpc::Status AuthenticatedServerUnaryReactor::Unauthenticated(std::string const& message) {
  return grpc::Status(grpc::UNAUTHENTICATED, message);
}

grpc::Status AuthenticatedServerUnaryReactor::InternalError(std::string const& message) {
  return grpc::Status(grpc::INTERNAL, message);
}

std::string AuthenticatedServerUnaryReactor::CreateSignedAuthenticationToken(hello_world::AuthenticationToken const* authenticationToken) {
  std::string payload;

  if (!authenticationToken->SerializeToString(&payload)) {
    throw std::runtime_error("Failed to serialize payload");
  }

  std::stringstream stream;
  stream << BinaryToUrlBase64(payload) << '.';

  Hmac hmac(m_signingKey);

  hmac.Update(payload);

  stream << BinaryToUrlBase64(hmac.Hash());

  return stream.str();
}

std::shared_ptr<hello_world::AuthenticationToken> AuthenticatedServerUnaryReactor::ParseAuthenticationToken(std::string_view value) {
  size_t dot1 = value.find('.');

  if (dot1 == std::string_view::npos) {
    spdlog::info("Invalid token");

    return nullptr;
  }

  std::string const payload = UrlBase64ToBinary(value.substr(0, dot1));

  Hmac hmac(m_signingKey);

  hmac.Update(payload);

  std::string const expectedSignature = hmac.Hash();

  std::string const signature = UrlBase64ToBinary(value.substr(dot1 + 1));

  if (signature != expectedSignature) {
    spdlog::info("Signature mismatch");

    return nullptr;
  }

  auto token = std::make_shared<hello_world::AuthenticationToken>();

  if (!token->ParseFromString(payload)) {
    spdlog::info("Invalid payload");

    return nullptr;
  }

  if (std::chrono::utc_clock::now().time_since_epoch().count() > token->expires()) {
    spdlog::info("Token expired");

    return nullptr;
  }

  return token;
}

std::shared_ptr<hello_world::AuthenticationToken> AuthenticatedServerUnaryReactor::GetAuthorizationToken(grpc::CallbackServerContext* context) {
  auto const& authMetadata = context->client_metadata();

  auto tokenPair = authMetadata.find("authorization");

  if (tokenPair == authMetadata.end()) {
    return nullptr;
  }

  auto const& value = tokenPair->second;

  if (!value.starts_with("Bearer ")) {
    spdlog::info("Authorization header is not a bearer");

    return nullptr;
  }

  auto authToken = ParseAuthenticationToken(std::string_view(tokenPair->second.data() + 7, tokenPair->second.size() - 7));

  if (!authToken) {
    return nullptr;
  }

  return authToken;
}

std::shared_ptr<hello_world::AuthenticationToken> AuthenticatedServerUnaryReactor::GetAuthorizationTokenOrFinish(grpc::CallbackServerContext* context) {
  auto token = GetAuthorizationToken(context);

  if (!token) {
    Finish(Unauthenticated());
  }

  return token;
}