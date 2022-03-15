// Copyright (C) 2022 Thanh Hai, Phan (haiphan93)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_TLS_CREDENTIALS_HPP
#define VSOMEIP_V3_CFG_TLS_CREDENTIALS_HPP

#include <vsomeip/primitive_types.hpp>

#include "internal.hpp"

namespace vsomeip_v3 {
namespace cfg {

struct tls_credentials {
    tls_credentials()
                :root_ca_path_(VSOMEIP_DEFAULT_TLS_CREDENTIAL_ROOT_CA_PATH),
                 certificate_path_(VSOMEIP_DEFAULT_TLS_CREDENTIAL_CERT_PATH),
                 private_key_path_(VSOMEIP_DEFAULT_TLS_CREDENTIAL_PRI_KEY_PATH) {}

    tls_credentials(const tls_credentials& rhs)
                :root_ca_path_(rhs.root_ca_path_),
                 certificate_path_(rhs.certificate_path_),
                 private_key_path_(rhs.private_key_path_) {}

    // path to credential files
    std::string root_ca_path_;
    std::string certificate_path_;
    std::string private_key_path_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_TLS_CREDENTIALS_HPP