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

#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <string>
#include <string_view>
#include <vector>

std::string BinaryToUrlBase64(std::string_view value);

std::string UrlBase64ToBinary(std::string_view value);

class Hmac {
 public:
  Hmac(std::string_view key);
  ~Hmac();

  void Update(std::string_view value);

  std::string Hash();

 private:
  EVP_MD const* const m_md;
  HMAC_CTX* const m_context;
};

#endif