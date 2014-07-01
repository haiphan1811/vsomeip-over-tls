// Copyright (C) 2014 BMW Group
// Author: Lutz Bichler (lutz.bichler@bmw.de)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ENDPOINT_HPP
#define VSOMEIP_ENDPOINT_HPP

#include <vsomeip/primitive_types.hpp>

namespace vsomeip {

class message_base;

class endpoint
{
public:
	virtual ~endpoint() {};

	virtual void start() = 0;
	virtual void stop() = 0;

	virtual bool send(const byte_t *_data, uint32_t _size, bool _flush = true) = 0;
	virtual bool flush() = 0;

	virtual void open_filter(service_t _service_id) = 0;
	virtual void close_filter(service_t _service_id) = 0;

	virtual void join(const std::string &_multicast_address) = 0;
	virtual void leave(const std::string &_multicast_address) = 0;

	virtual void enable_magic_cookies() = 0;
	virtual void disable_magic_cookies() = 0;
};

} // namespace vsomeip

#endif // VSOMEIP_ENDPOINT_HPP