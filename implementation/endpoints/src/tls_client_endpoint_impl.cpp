// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/endpoint_host.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../include/tls_client_endpoint_impl.hpp"
#include "../../utility/include/utility.hpp"
#include "../../utility/include/byteorder.hpp"

namespace ip = boost::asio::ip;

namespace vsomeip_v3 {

tls_client_endpoint_impl::tls_client_endpoint_impl(
        const std::shared_ptr<endpoint_host>& _endpoint_host,
        const std::shared_ptr<routing_host>& _routing_host,
        const endpoint_type& _local,
        const endpoint_type& _remote,
        boost::asio::io_service &_io,
        const std::shared_ptr<configuration>& _configuration)
    : tcp_client_endpoint_base_impl(_endpoint_host, _routing_host, _local,
                                    _remote, _io,
                                    _configuration->get_max_message_size_reliable(
                                            _remote.address().to_string(),
                                            _remote.port()),
                                    _configuration->get_endpoint_queue_limit(
                                                    _remote.address().to_string(),
                                                    _remote.port()),
                                    _configuration),
      ssl_context_(boost::asio::ssl::context::tlsv12_client),
      ssl_socket_(nullptr),
      recv_buffer_size_initial_(VSOMEIP_SOMEIP_HEADER_SIZE),
      recv_buffer_(std::make_shared<message_buffer_t>(recv_buffer_size_initial_, 0)),
      shrink_count_(0),
      buffer_shrink_threshold_(configuration_->get_buffer_shrink_threshold()),
      remote_address_(_remote.address()),
      remote_port_(_remote.port()),
      last_cookie_sent_(std::chrono::steady_clock::now() - std::chrono::seconds(11)),
      // send timeout after 2/3 of configured ttl, warning after 1/3
      send_timeout_(configuration_->get_sd_ttl() * 666),
      send_timeout_warning_(send_timeout_ / 2),
      tcp_restart_aborts_max_(configuration_->get_max_tcp_restart_aborts()),
      tcp_connect_time_max_(configuration_->get_max_tcp_connect_time()),
      aborted_restart_count_(0),
      sent_timer_(_io) {

    is_supporting_magic_cookies_ = true;
    socket_.reset(nullptr);
    try {
        const auto& verify_certs_path = configuration_->get_client_tls_credentials().root_ca_path_;
        VSOMEIP_TRACE << "tls_client_endpoint_impl::" << __func__ << " load_verify_file" << verify_certs_path;
        if (!verify_certs_path.empty()) {
            ssl_context_.load_verify_file(verify_certs_path);
            ssl_context_.set_verify_mode(boost::asio::ssl::verify_peer
                                        | boost::asio::ssl::verify_fail_if_no_peer_cert);
        }
        ssl_context_.set_password_callback(std::bind(&tls_client_endpoint_impl::get_password_cbk, this));
        ssl_context_.use_certificate_file(configuration_->get_client_tls_credentials().certificate_path_,
                                          boost::asio::ssl::context::pem);
        ssl_context_.use_private_key_file(configuration_->get_client_tls_credentials().private_key_path_,
                                          boost::asio::ssl::context::pem);
    }
    catch (const boost::system::system_error &e) {
        VSOMEIP_ERROR << "tls_client_endpoint_impl::" << __func__ << " " << e.what();
    }
    ssl_socket_.reset(new ssl_socket_t(_io, ssl_context_));
}

tls_client_endpoint_impl::~tls_client_endpoint_impl() {
    std::shared_ptr<endpoint_host> its_host = endpoint_host_.lock();
    if (its_host) {
        its_host->release_port(local_.port(), true);
    }
}

bool tls_client_endpoint_impl::is_local() const {
    return false;
}

void tls_client_endpoint_impl::start() {
    connect();
}

void tls_client_endpoint_impl::restart(bool _force) {
    if (!_force && state_ == cei_state_e::CONNECTING) {
        std::chrono::steady_clock::time_point its_current
            = std::chrono::steady_clock::now();
        long its_connect_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                its_current - connect_timepoint_).count();
        if (aborted_restart_count_ < tcp_restart_aborts_max_
                && its_connect_duration < tcp_connect_time_max_) {
            aborted_restart_count_++;
            return;
        } else {
            VSOMEIP_WARNING << "tce::restart: maximum number of aborted restarts ["
                    << tcp_restart_aborts_max_ << "] reached! its_connect_duration: "
                    << its_connect_duration;
        }
    }
    state_ = cei_state_e::CONNECTING;
    std::string address_port_local;
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        address_port_local = get_address_port_local();
        shutdown_and_close_ssl_socket_unlocked(true);
        recv_buffer_ = std::make_shared<message_buffer_t>(recv_buffer_size_initial_, 0);
    }
    was_not_connected_ = true;
    reconnect_counter_ = 0;
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        for (const auto&m : queue_) {
            const service_t its_service = VSOMEIP_BYTES_TO_WORD(
                    (*m)[VSOMEIP_SERVICE_POS_MIN],
                    (*m)[VSOMEIP_SERVICE_POS_MAX]);
            const method_t its_method = VSOMEIP_BYTES_TO_WORD(
                    (*m)[VSOMEIP_METHOD_POS_MIN],
                    (*m)[VSOMEIP_METHOD_POS_MAX]);
            const client_t its_client = VSOMEIP_BYTES_TO_WORD(
                    (*m)[VSOMEIP_CLIENT_POS_MIN],
                    (*m)[VSOMEIP_CLIENT_POS_MAX]);
            const session_t its_session = VSOMEIP_BYTES_TO_WORD(
                    (*m)[VSOMEIP_SESSION_POS_MIN],
                    (*m)[VSOMEIP_SESSION_POS_MAX]);
            VSOMEIP_WARNING << "tce::restart: dropping message: "
                    << "remote:" << get_address_port_remote() << " ("
                    << std::hex << std::setw(4) << std::setfill('0') << its_client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << its_service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << its_method << "."
                    << std::hex << std::setw(4) << std::setfill('0') << its_session << "]"
                    << " size: " << std::dec << m->size();
        }
        queue_.clear();
        queue_size_ = 0;
    }
    VSOMEIP_WARNING << "tce::restart: local: " << address_port_local
            << " remote: " << get_address_port_remote();
    start_connect_timer();
}

bool tls_client_endpoint_impl::verify_certificate_cbk(bool preverified, boost::asio::ssl::verify_context& ctx) {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    VSOMEIP_INFO << "Verifying " << subject_name;

    return preverified;
}

void tls_client_endpoint_impl::connect() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    if (ssl_socket_) {
        ssl_socket_->lowest_layer().open(remote_.protocol(), its_error);
    } else {
        its_error = boost::asio::error::broken_pipe;
    }

    VSOMEIP_TRACE << "tls_client_endpoint_impl::" << __func__
                  << " open remote_.protocol() ec=" << its_error.message();

    if (!its_error || its_error == boost::asio::error::already_open) {
        // Nagle algorithm off
        ssl_socket_->lowest_layer().set_option(ip::tcp::no_delay(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tls_client_endpoint::connect: couldn't disable "
                    << "Nagle algorithm: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

        ssl_socket_->lowest_layer().set_option(boost::asio::socket_base::keep_alive(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tls_client_endpoint::connect: couldn't enable "
                    << "keep_alive: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

        // Enable SO_REUSEADDR to avoid bind problems with services going offline
        // and coming online again and the user has specified only a small number
        // of ports in the clients section for one service instance
        ssl_socket_->lowest_layer().set_option(boost::asio::socket_base::reuse_address(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tls_client_endpoint::connect: couldn't enable "
                    << "SO_REUSEADDR: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }
        ssl_socket_->lowest_layer().set_option(boost::asio::socket_base::linger(true, 0), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tls_client_endpoint::connect: couldn't enable "
                    << "SO_LINGER: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

#ifndef _WIN32
        // If specified, bind to device
        std::string its_device(configuration_->get_device());
        if (its_device != "") {
            if (setsockopt(ssl_socket_->lowest_layer().native_handle(),
                    SOL_SOCKET, SO_BINDTODEVICE, its_device.c_str(), (int)its_device.size()) == -1) {
                VSOMEIP_WARNING << "TCP Client: Could not bind to device \"" << its_device << "\"";
            }
        }
#endif

        // Bind address and, optionally, port.
        boost::system::error_code its_bind_error;
        ssl_socket_->lowest_layer().bind(local_, its_bind_error);
        if(its_bind_error) {
            VSOMEIP_WARNING << "tls_client_endpoint::connect: "
                    "Error binding socket: " << its_bind_error.message()
                    << " remote:" << get_address_port_remote();
            try {
                // don't connect on bind error to avoid using a random port
                strand_.post(std::bind(&client_endpoint_impl::connect_cbk,
                                shared_from_this(), its_bind_error));
            } catch (const std::exception &e) {
                VSOMEIP_ERROR << "tls_client_endpoint_impl::connect: "
                        << e.what() << " remote:" << get_address_port_remote();
            }
            return;
        }

        ssl_socket_->set_verify_callback(std::bind(&tls_client_endpoint_impl::verify_certificate_cbk,
                    std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                    std::placeholders::_1,  std::placeholders::_2));

        state_ = cei_state_e::CONNECTING;
        connect_timepoint_ = std::chrono::steady_clock::now();
        aborted_restart_count_ = 0;

        ssl_endpoint_t ep;
        ep = ssl_endpoint_t::create(remote_, remote_.address().to_string(), "service_name");
        VSOMEIP_TRACE << "tls_client_endpoint_impl::connect: "
                      << "Address=" << remote_.address().to_string()
                      << "&Port=" << remote_.port();

        boost::asio::async_connect(ssl_socket_->lowest_layer(), ep,
            strand_.wrap(
                std::bind(
                    &tls_client_endpoint_impl::connect_cbk,
                    std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                    std::placeholders::_1
                )
            )
        );
    } else {
        VSOMEIP_WARNING << "tls_client_endpoint::connect: Error opening socket: "
                << its_error.message() << " remote:" << get_address_port_remote();
        strand_.post(std::bind(&tls_client_endpoint_impl::connect_cbk,
                        std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()), its_error));
    }
}

void tls_client_endpoint_impl::receive() {
    message_buffer_ptr_t its_recv_buffer;
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        its_recv_buffer = recv_buffer_;
    }
    receive(its_recv_buffer, 0, 0);
}

void tls_client_endpoint_impl::receive(message_buffer_ptr_t  _recv_buffer,
             std::size_t _recv_buffer_size,
             std::size_t _missing_capacity) {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if(ssl_socket_ != nullptr && ssl_socket_->lowest_layer().is_open()) {
        const std::size_t its_capacity(_recv_buffer->capacity());
        size_t buffer_size = its_capacity - _recv_buffer_size;
        try {
            if (_missing_capacity) {
                if (_missing_capacity > MESSAGE_SIZE_UNLIMITED) {
                    return;
                }
                const std::size_t its_required_capacity(_recv_buffer_size + _missing_capacity);
                if (its_capacity < its_required_capacity) {
                    _recv_buffer->reserve(its_required_capacity);
                    _recv_buffer->resize(its_required_capacity, 0x0);
                    if (_recv_buffer->size() > 1048576) {
                        VSOMEIP_INFO << "tce: recv_buffer size is: " <<
                                _recv_buffer->size()
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote();
                    }
                }
                buffer_size = _missing_capacity;
            } else if (buffer_shrink_threshold_
                    && shrink_count_ > buffer_shrink_threshold_
                    && _recv_buffer_size == 0) {
                _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                _recv_buffer->shrink_to_fit();
                buffer_size = recv_buffer_size_initial_;
                shrink_count_ = 0;
            }
        } catch (const std::exception &e) {
            handle_recv_buffer_exception(e, _recv_buffer, _recv_buffer_size);
            // don't start receiving again
            return;
        }

        boost::asio::async_read(*ssl_socket_,
            boost::asio::buffer(&(*_recv_buffer)[_recv_buffer_size], buffer_size),
            strand_.wrap(
                std::bind(
                    &tls_client_endpoint_impl::receive_cbk,
                    std::dynamic_pointer_cast< tls_client_endpoint_impl >(shared_from_this()),
                    std::placeholders::_1,
                    std::placeholders::_2,
                    _recv_buffer,
                    _recv_buffer_size
                )
            )
        );
    }
}

bool tls_client_endpoint_impl::is_open_connection() const {
    if (ssl_socket_) {
        return ssl_socket_->lowest_layer().is_open();
    }
    return false;
}

void tls_client_endpoint_impl::send_queued() {
    message_buffer_ptr_t its_buffer;
    if(queue_.size()) {
        its_buffer = queue_.front();
    } else {
        return;
    }
    const service_t its_service = VSOMEIP_BYTES_TO_WORD(
            (*its_buffer)[VSOMEIP_SERVICE_POS_MIN],
            (*its_buffer)[VSOMEIP_SERVICE_POS_MAX]);
    const method_t its_method = VSOMEIP_BYTES_TO_WORD(
            (*its_buffer)[VSOMEIP_METHOD_POS_MIN],
            (*its_buffer)[VSOMEIP_METHOD_POS_MAX]);
    const client_t its_client = VSOMEIP_BYTES_TO_WORD(
            (*its_buffer)[VSOMEIP_CLIENT_POS_MIN],
            (*its_buffer)[VSOMEIP_CLIENT_POS_MAX]);
    const session_t its_session = VSOMEIP_BYTES_TO_WORD(
            (*its_buffer)[VSOMEIP_SESSION_POS_MIN],
            (*its_buffer)[VSOMEIP_SESSION_POS_MAX]);

    if (has_enabled_magic_cookies_) {
        const std::chrono::steady_clock::time_point now =
                std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_cookie_sent_) > std::chrono::milliseconds(10000)) {
            send_magic_cookie(its_buffer);
            last_cookie_sent_ = now;
        }
    }


#if 0
    std::stringstream msg;
    msg << "tcei<" << remote_.address() << ":"
        << std::dec << remote_.port()  << ">::sq: ";
    for (std::size_t i = 0; i < its_buffer->size(); i++)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int)(*its_buffer)[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        if (ssl_socket_ != nullptr && ssl_socket_->lowest_layer().is_open()) {
            {
                std::lock_guard<std::mutex> its_sent_lock(sent_mutex_);
                is_sending_ = true;
            }
            boost::asio::async_write(
                *ssl_socket_,
                boost::asio::buffer(*its_buffer),
                std::bind(&tls_client_endpoint_impl::write_completion_condition,
                          std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                          std::placeholders::_1,
                          std::placeholders::_2,
                          its_buffer->size(),
                          its_service, its_method, its_client, its_session,
                          std::chrono::steady_clock::now()),
                std::bind(
                    &tls_client_endpoint_impl::send_cbk,
                    std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                    std::placeholders::_1,
                    std::placeholders::_2,
                    its_buffer
                )
            );
        }
    }
}

void tls_client_endpoint_impl::get_configured_times_from_endpoint(
        service_t _service, method_t _method,
        std::chrono::nanoseconds *_debouncing,
        std::chrono::nanoseconds *_maximum_retention) const {
    configuration_->get_configured_timing_requests(_service,
            remote_address_.to_string(), remote_port_, _method,
            _debouncing, _maximum_retention);
}

bool tls_client_endpoint_impl::get_remote_address(
        boost::asio::ip::address &_address) const {
    if (remote_address_.is_unspecified()) {
        return false;
    }
    _address = remote_address_;
    return true;
}

void tls_client_endpoint_impl::set_local_port() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    if (ssl_socket_ != nullptr && ssl_socket_->lowest_layer().is_open()) {
        endpoint_type its_endpoint = ssl_socket_->lowest_layer().local_endpoint(its_error);
        if (!its_error) {
            local_port_ = its_endpoint.port();
        } else {
            VSOMEIP_WARNING << "tls_client_endpoint_impl::set_local_port() "
                    << " couldn't get local_endpoint: " << its_error.message();
        }
    }
}

std::size_t tls_client_endpoint_impl::write_completion_condition(
        const boost::system::error_code& _error, std::size_t _bytes_transferred,
        std::size_t _bytes_to_send, service_t _service, method_t _method,
        client_t _client, session_t _session,
        const std::chrono::steady_clock::time_point _start) {

    if (_error) {
        VSOMEIP_ERROR << "tce::write_completion_condition: "
                << _error.message() << "(" << std::dec << _error.value()
                << ") bytes transferred: " << std::dec << _bytes_transferred
                << " bytes to sent: " << std::dec << _bytes_to_send << " "
                << "remote:" << get_address_port_remote() << " ("
                << std::hex << std::setw(4) << std::setfill('0') << _client <<"): ["
                << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                << std::hex << std::setw(4) << std::setfill('0') << _method << "."
                << std::hex << std::setw(4) << std::setfill('0') << _session << "]";
        return 0;
    }

    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    const std::chrono::milliseconds passed = std::chrono::duration_cast<std::chrono::milliseconds>(now - _start);
    if (passed > send_timeout_warning_) {
        if (passed > send_timeout_) {
            VSOMEIP_ERROR << "tce::write_completion_condition: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") took longer than " << std::dec << send_timeout_.count()
                    << "ms bytes transferred: " << std::dec << _bytes_transferred
                    << " bytes to sent: " << std::dec << _bytes_to_send << " "
                    << "remote:" << get_address_port_remote() << " ("
                    << std::hex << std::setw(4) << std::setfill('0') << _client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _method << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _session << "]";
        } else {
            VSOMEIP_WARNING << "tce::write_completion_condition: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") took longer than " << std::dec << send_timeout_warning_.count()
                    << "ms bytes transferred: " << std::dec << _bytes_transferred
                    << " bytes to sent: " << std::dec << _bytes_to_send << " "
                    << "remote:" << get_address_port_remote() << " ("
                    << std::hex << std::setw(4) << std::setfill('0') << _client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _method << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _session << "]";
        }
    }
    return _bytes_to_send - _bytes_transferred;
}

std::uint16_t tls_client_endpoint_impl::get_remote_port() const {
    return remote_port_;
}

bool tls_client_endpoint_impl::is_reliable() const {
  return true;
}

bool tls_client_endpoint_impl::is_magic_cookie(const message_buffer_ptr_t& _recv_buffer,
                                               size_t _offset) const {
    return (0 == std::memcmp(SERVICE_COOKIE, &(*_recv_buffer)[_offset], sizeof(SERVICE_COOKIE)));
}

void tls_client_endpoint_impl::send_magic_cookie(message_buffer_ptr_t &_buffer) {
    if (max_message_size_ == MESSAGE_SIZE_UNLIMITED
            || max_message_size_ - _buffer->size() >=
        VSOMEIP_SOMEIP_HEADER_SIZE + VSOMEIP_SOMEIP_MAGIC_COOKIE_SIZE) {
        _buffer->insert(
            _buffer->begin(),
            CLIENT_COOKIE,
            CLIENT_COOKIE + sizeof(CLIENT_COOKIE)
        );
        queue_size_ += sizeof(CLIENT_COOKIE);
    } else {
        VSOMEIP_WARNING << "Packet full. Cannot insert magic cookie!";
    }
}

void tls_client_endpoint_impl::connect_cbk(boost::system::error_code const &_error) {
    VSOMEIP_TRACE << "tls_client_endpoint_impl::" << __func__ << " ec=" << _error.message();
    if (_error == boost::asio::error::operation_aborted
            || tcp_client_endpoint_base_impl::sending_blocked_) {
        // endpoint was stopped
        shutdown_and_close_ssl_socket(false);
        return;
    }
    std::shared_ptr<endpoint_host> its_host = this->endpoint_host_.lock();
    if (its_host) {
        if (_error && _error != boost::asio::error::already_connected) {
            shutdown_and_close_ssl_socket(true);

            if (state_ != cei_state_e::ESTABLISHED) {
                state_ = cei_state_e::CLOSED;
                its_host->on_disconnect(this->shared_from_this());
            }
            if (get_max_allowed_reconnects() == MAX_RECONNECTS_UNLIMITED ||
                get_max_allowed_reconnects() >= ++reconnect_counter_) {
                start_connect_timer();
            } else {
                max_allowed_reconnects_reached();
            }
            // Double the timeout as long as the maximum allowed is larger
            if (connect_timeout_ < VSOMEIP_MAX_CONNECT_TIMEOUT)
                connect_timeout_ = (connect_timeout_ << 1);
        } else {
            {
                std::lock_guard<std::mutex> its_lock(connect_timer_mutex_);
                connect_timer_.cancel();
            }
            connect_timeout_ = VSOMEIP_DEFAULT_CONNECT_TIMEOUT; // TODO: use config variable
            reconnect_counter_ = 0;
            set_local_port();

            {
                std::lock_guard<std::mutex> its_lock(socket_mutex_);
                if (ssl_socket_)
                    ssl_socket_->async_handshake(boost::asio::ssl::stream_base::client,
                                         std::bind(&tls_client_endpoint_impl::handshake_cbk,
                                         std::static_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                                         std::placeholders::_1));
            }
        }
    }
}

void tls_client_endpoint_impl::handshake_cbk(boost::system::error_code const &_error) {
    VSOMEIP_TRACE << "tls_client_endpoint_impl::" << __func__ 
                  << " ec=" << _error.value() << "(" << _error.message() << ")";
    if (_error) {
        shutdown_and_close_ssl_socket(true);
    } else {
        std::shared_ptr<endpoint_host> its_host = this->endpoint_host_.lock();
        if (its_host) {
            if (was_not_connected_) {
                was_not_connected_ = false;
                std::lock_guard<std::mutex> its_lock(mutex_);
                if (queue_.size() > 0) {
                    send_queued();
                    VSOMEIP_WARNING << __func__ << ": resume sending to: "
                            << get_remote_information();
                }
            }
            if (state_ != cei_state_e::ESTABLISHED) {
                its_host->on_connect(shared_from_this());
            }
            receive();
        }
    }
}

void tls_client_endpoint_impl::receive_cbk(
        boost::system::error_code const &_error, std::size_t _bytes,
        const message_buffer_ptr_t& _recv_buffer, std::size_t _recv_buffer_size) {
    if (_error == boost::asio::error::operation_aborted) {
        // endpoint was stopped
        return;
    }
#if 0
    std::stringstream msg;
    msg << "cei::rcb (" << _error.message() << "): ";
    for (std::size_t i = 0; i < _bytes + _recv_buffer_size; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int) (_recv_buffer)[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    std::unique_lock<std::mutex> its_lock(socket_mutex_);
    std::shared_ptr<routing_host> its_host = routing_host_.lock();
    if (its_host) {
        std::uint32_t its_missing_capacity(0);
        if (!_error && 0 < _bytes) {
            if (_recv_buffer_size + _bytes < _recv_buffer_size) {
                VSOMEIP_ERROR << "receive buffer overflow in tcp client endpoint ~> abort!";
                return;
            }
            _recv_buffer_size += _bytes;

            size_t its_iteration_gap = 0;
            bool has_full_message(false);
            do {
                uint64_t read_message_size
                    = utility::get_message_size(&(*_recv_buffer)[its_iteration_gap],
                            _recv_buffer_size);
                if (read_message_size > MESSAGE_SIZE_UNLIMITED) {
                    VSOMEIP_ERROR << "Message size exceeds allowed maximum!";
                    return;
                }
                uint32_t current_message_size = static_cast<uint32_t>(read_message_size);
                has_full_message = (current_message_size > VSOMEIP_RETURN_CODE_POS
                                 && current_message_size <= _recv_buffer_size);
                if (has_full_message) {
                    bool needs_forwarding(true);
                    if (is_magic_cookie(_recv_buffer, its_iteration_gap)) {
                        has_enabled_magic_cookies_ = true;
                    } else {
                        if (has_enabled_magic_cookies_) {
                            uint32_t its_offset = find_magic_cookie(&(*_recv_buffer)[its_iteration_gap],
                                    (uint32_t) _recv_buffer_size);
                            if (its_offset < current_message_size) {
                                VSOMEIP_ERROR << "Message includes Magic Cookie. Ignoring it.";
                                current_message_size = its_offset;
                                needs_forwarding = false;
                            }
                        }
                    }
                    if (needs_forwarding) {
                        if (!has_enabled_magic_cookies_) {
                            its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                 current_message_size, this,
                                                 boost::asio::ip::address(),
                                                 VSOMEIP_ROUTING_CLIENT,
                                                 std::make_pair(ANY_UID, ANY_GID),
                                                 remote_address_,
                                                 remote_port_);
                        } else {
                            // Only call on_message without a magic cookie in front of the buffer!
                            if (!is_magic_cookie(_recv_buffer, its_iteration_gap)) {
                                its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                     current_message_size, this,
                                                     boost::asio::ip::address(),
                                                     VSOMEIP_ROUTING_CLIENT,
                                                     std::make_pair(ANY_UID, ANY_GID),
                                                     remote_address_,
                                                     remote_port_);
                            }
                        }
                    }
                    calculate_shrink_count(_recv_buffer, _recv_buffer_size);
                    _recv_buffer_size -= current_message_size;
                    its_iteration_gap += current_message_size;
                    its_missing_capacity = 0;
                } else if (has_enabled_magic_cookies_ && _recv_buffer_size > 0) {
                    const uint32_t its_offset = find_magic_cookie(
                            &(*_recv_buffer)[its_iteration_gap], _recv_buffer_size);
                    if (its_offset < _recv_buffer_size) {
                        _recv_buffer_size -= its_offset;
                        its_iteration_gap += its_offset;
                        has_full_message = true; // trigger next loop
                        VSOMEIP_ERROR << "Detected Magic Cookie within message data."
                            << " Resyncing. local: " << get_address_port_local()
                            << " remote: " << get_address_port_remote();
                    }
                }

                if (!has_full_message) {
                    if (_recv_buffer_size > VSOMEIP_RETURN_CODE_POS &&
                        ((*recv_buffer_)[its_iteration_gap + VSOMEIP_PROTOCOL_VERSION_POS] != VSOMEIP_PROTOCOL_VERSION ||
                         !utility::is_valid_message_type(static_cast<message_type_e>((*recv_buffer_)[its_iteration_gap + VSOMEIP_MESSAGE_TYPE_POS])) ||
                         !utility::is_valid_return_code(static_cast<return_code_e>((*recv_buffer_)[its_iteration_gap + VSOMEIP_RETURN_CODE_POS]))
                        )) {
                        if ((*recv_buffer_)[its_iteration_gap + VSOMEIP_PROTOCOL_VERSION_POS] != VSOMEIP_PROTOCOL_VERSION) {
                            VSOMEIP_ERROR << "tce: Wrong protocol version: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_PROTOCOL_VERSION_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                            // ensure to send back a message w/ wrong protocol version
                            its_lock.unlock();
                            its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                 VSOMEIP_SOMEIP_HEADER_SIZE + 8, this,
                                                 boost::asio::ip::address(),
                                                 VSOMEIP_ROUTING_CLIENT,
                                                 std::make_pair(ANY_UID, ANY_GID),
                                                 remote_address_,
                                                 remote_port_);
                            its_lock.lock();
                        } else if (!utility::is_valid_message_type(static_cast<message_type_e>(
                                (*recv_buffer_)[its_iteration_gap + VSOMEIP_MESSAGE_TYPE_POS]))) {
                            VSOMEIP_ERROR << "tce: Invalid message type: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_MESSAGE_TYPE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                        } else if (!utility::is_valid_return_code(static_cast<return_code_e>(
                                (*recv_buffer_)[its_iteration_gap + VSOMEIP_RETURN_CODE_POS]))) {
                            VSOMEIP_ERROR << "tce: Invalid return code: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_RETURN_CODE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                        }
                        state_ = cei_state_e::CONNECTING;
                        shutdown_and_close_ssl_socket_unlocked(false);
                        its_lock.unlock();

                        // wait_until_sent interprets "no error" as timeout.
                        // Therefore call it with an error.
                        wait_until_sent(boost::asio::error::operation_aborted);
                        return;
                    } else if (max_message_size_ != MESSAGE_SIZE_UNLIMITED &&
                            current_message_size > max_message_size_) {
                        _recv_buffer_size = 0;
                        _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                        _recv_buffer->shrink_to_fit();
                        if (has_enabled_magic_cookies_) {
                            VSOMEIP_ERROR << "Received a TCP message which exceeds "
                                          << "maximum message size ("
                                          << std::dec << current_message_size
                                          << "). Magic Cookies are enabled: "
                                          << "Resetting receiver. local: "
                                          << get_address_port_local() << " remote: "
                                          << get_address_port_remote();
                        } else {
                            VSOMEIP_ERROR << "Received a TCP message which exceeds "
                                          << "maximum message size ("
                                          << std::dec << current_message_size
                                          << ") Magic cookies are disabled, "
                                          << "Restarting connection. "
                                          << "local: " << get_address_port_local()
                                          << " remote: " << get_address_port_remote();
                            state_ = cei_state_e::CONNECTING;
                            shutdown_and_close_ssl_socket_unlocked(false);
                            its_lock.unlock();

                            // wait_until_sent interprets "no error" as timeout.
                            // Therefore call it with an error.
                            wait_until_sent(boost::asio::error::operation_aborted);
                            return;
                        }
                    } else if (current_message_size > _recv_buffer_size) {
                            its_missing_capacity = current_message_size
                                    - static_cast<std::uint32_t>(_recv_buffer_size);
                    } else if (VSOMEIP_SOMEIP_HEADER_SIZE > _recv_buffer_size) {
                            its_missing_capacity = VSOMEIP_SOMEIP_HEADER_SIZE
                                    - static_cast<std::uint32_t>(_recv_buffer_size);
                    } else if (has_enabled_magic_cookies_ && _recv_buffer_size > 0) {
                        // no need to check for magic cookie here again: has_full_message
                        // would have been set to true if there was one present in the data
                        _recv_buffer_size = 0;
                        _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                        _recv_buffer->shrink_to_fit();
                        its_missing_capacity = 0;
                        VSOMEIP_ERROR << "tce::c<" << this
                                << ">rcb: recv_buffer_capacity: "
                                << _recv_buffer->capacity()
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote()
                                << ". Didn't find magic cookie in broken data, trying to resync.";
                    } else {
                        VSOMEIP_ERROR << "tce::c<" << this
                                << ">rcb: recv_buffer_size is: " << std::dec
                                << _recv_buffer_size << " but couldn't read "
                                "out message_size. recv_buffer_capacity: "
                                << _recv_buffer->capacity()
                                << " its_iteration_gap: " << its_iteration_gap
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote()
                                << ". Restarting connection due to missing/broken data TCP stream.";
                        state_ = cei_state_e::CONNECTING;
                        shutdown_and_close_ssl_socket_unlocked(false);
                        its_lock.unlock();

                        // wait_until_sent interprets "no error" as timeout.
                        // Therefore call it with an error.
                        wait_until_sent(boost::asio::error::operation_aborted);
                        return;
                    }
                }
            } while (has_full_message && _recv_buffer_size);
            if (its_iteration_gap) {
                // Copy incomplete message to front for next receive_cbk iteration
                for (size_t i = 0; i < _recv_buffer_size; ++i) {
                    (*_recv_buffer)[i] = (*_recv_buffer)[i + its_iteration_gap];
                }
                // Still more capacity needed after shifting everything to front?
                if (its_missing_capacity &&
                        its_missing_capacity <= _recv_buffer->capacity() - _recv_buffer_size) {
                    its_missing_capacity = 0;
                }
            }
            its_lock.unlock();
            receive(_recv_buffer, _recv_buffer_size, its_missing_capacity);
        } else {
            VSOMEIP_WARNING << "tls_client_endpoint receive_cbk: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") local: " << get_address_port_local()
                    << " remote: " << get_address_port_remote();
            if (_error ==  boost::asio::error::eof ||
                    _error == boost::asio::error::timed_out ||
                    _error == boost::asio::error::bad_descriptor ||
                    _error == boost::asio::error::connection_reset) {
                if (state_ == cei_state_e::CONNECTING) {
                    VSOMEIP_WARNING << "tls_client_endpoint receive_cbk already"
                            " restarting" << get_remote_information();
                } else {
                    VSOMEIP_WARNING << "tls_client_endpoint receive_cbk restarting.";
                    state_ = cei_state_e::CONNECTING;
                    shutdown_and_close_ssl_socket_unlocked(false);
                    its_lock.unlock();

                    // wait_until_sent interprets "no error" as timeout.
                    // Therefore call it with an error.
                    wait_until_sent(boost::asio::error::operation_aborted);
                }
            } else {
                its_lock.unlock();
                receive(_recv_buffer, _recv_buffer_size, its_missing_capacity);
            }
        }
    }
}

void tls_client_endpoint_impl::calculate_shrink_count(const message_buffer_ptr_t& _recv_buffer,
                                                      std::size_t _recv_buffer_size) {
    if (buffer_shrink_threshold_) {
        if (_recv_buffer->capacity() != recv_buffer_size_initial_) {
            if (_recv_buffer_size < (_recv_buffer->capacity() >> 1)) {
                shrink_count_++;
            } else {
                shrink_count_ = 0;
            }
        }
    }
}

const std::string tls_client_endpoint_impl::get_address_port_remote() const {
    boost::system::error_code ec;
    std::string its_address_port;
    its_address_port.reserve(21);
    boost::asio::ip::address its_address;
    if (get_remote_address(its_address)) {
        its_address_port += its_address.to_string();
    }
    its_address_port += ":";
    its_address_port += std::to_string(remote_port_);
    return its_address_port;
}

const std::string tls_client_endpoint_impl::get_address_port_local() const {
    std::string its_address_port;
    its_address_port.reserve(21);
    boost::system::error_code ec;
    if (ssl_socket_ != nullptr && ssl_socket_->lowest_layer().is_open()) {
        endpoint_type its_local_endpoint = ssl_socket_->lowest_layer().local_endpoint(ec);
        if (!ec) {
            its_address_port += its_local_endpoint.address().to_string(ec);
            its_address_port += ":";
            its_address_port.append(std::to_string(its_local_endpoint.port()));
        }
    }
    return its_address_port;
}

void tls_client_endpoint_impl::handle_recv_buffer_exception(
        const std::exception &_e,
        const message_buffer_ptr_t& _recv_buffer,
        std::size_t _recv_buffer_size) {
    boost::system::error_code ec;

    std::stringstream its_message;
    its_message <<"tls_client_endpoint_impl::connection catched exception"
            << _e.what() << " local: " << get_address_port_local()
            << " remote: " << get_address_port_remote()
            << " shutting down connection. Start of buffer: ";

    for (std::size_t i = 0; i < _recv_buffer_size && i < 16; i++) {
        its_message << std::setw(2) << std::setfill('0') << std::hex
            << (int) ((*_recv_buffer)[i]) << " ";
    }

    its_message << " Last 16 Bytes captured: ";
    for (int i = 15; _recv_buffer_size > 15 && i >= 0; i--) {
        its_message << std::setw(2) << std::setfill('0') << std::hex
            << (int) ((*_recv_buffer)[static_cast<size_t>(i)]) << " ";
    }
    VSOMEIP_ERROR << its_message.str();
    _recv_buffer->clear();
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        sending_blocked_ = true;
    }
    {
        std::lock_guard<std::mutex> its_lock(connect_timer_mutex_);
        boost::system::error_code ec;
        connect_timer_.cancel(ec);
    }
    boost::system::error_code its_error;
    if (ssl_socket_ != nullptr) {
        try {
            ssl_socket_->shutdown(its_error);
            if (ssl_socket_->lowest_layer().is_open()) {
                ssl_socket_->lowest_layer().shutdown(socket_type::shutdown_both, its_error);
                ssl_socket_->lowest_layer().close(its_error);
            }
        } catch (const boost::system::system_error& e) {
            VSOMEIP_ERROR << "tls_client_endpoint_impl::" << __func__ << ": " << e.what();
        }
    }
}

void tls_client_endpoint_impl::print_status() {
    std::size_t its_data_size(0);
    std::size_t its_queue_size(0);
    std::size_t its_receive_buffer_capacity(0);
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        its_queue_size = queue_.size();
        its_data_size = queue_size_;
    }
    std::string local;
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        local = get_address_port_local();
        its_receive_buffer_capacity = recv_buffer_->capacity();
    }

    VSOMEIP_INFO << "status tce: " << local << " -> "
            << get_address_port_remote()
            << " queue: " << std::dec << its_queue_size
            << " data: " << std::dec << its_data_size
            << " recv_buffer: " << std::dec << its_receive_buffer_capacity;
}

std::string tls_client_endpoint_impl::get_remote_information() const {
    boost::system::error_code ec;
    return remote_.address().to_string(ec) + ":"
            + std::to_string(remote_.port());
}

void tls_client_endpoint_impl::send_cbk(boost::system::error_code const &_error,
                                        std::size_t _bytes,
                                        const message_buffer_ptr_t& _sent_msg) {
    (void)_bytes;

    {
        // Signal that the current send operation has finished.
        // Note: Waiting is always done after having closed the socket.
        //       Therefore, no new send operation will be scheduled.
        std::lock_guard<std::mutex> its_sent_lock(sent_mutex_);
        is_sending_ = false;

        boost::system::error_code ec;
        sent_timer_.cancel(ec);
    }

    if (!_error) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        if (queue_.size() > 0) {
            queue_size_ -= queue_.front()->size();
            queue_.pop_front();
            send_queued();
        }
    } else if (_error == boost::system::errc::destination_address_required) {
        VSOMEIP_WARNING << "tce::send_cbk received error: " << _error.message()
                << " (" << std::dec << _error.value() << ") "
                << get_remote_information();
        was_not_connected_ = true;
    } else if (_error == boost::asio::error::operation_aborted) {
        // endpoint was stopped
        shutdown_and_close_ssl_socket(false);
    } else {
        if (state_ == cei_state_e::CONNECTING) {
            VSOMEIP_WARNING << "tce::send_cbk endpoint is already restarting:"
                    << get_remote_information();
        } else {
            state_ = cei_state_e::CONNECTING;
            shutdown_and_close_ssl_socket(false);
            std::shared_ptr<endpoint_host> its_host = endpoint_host_.lock();
            if (its_host) {
                its_host->on_disconnect(shared_from_this());
            }
            restart(true);
        }
        service_t its_service(0);
        method_t its_method(0);
        client_t its_client(0);
        session_t its_session(0);
        if (_sent_msg && _sent_msg->size() > VSOMEIP_SESSION_POS_MAX) {
            its_service = VSOMEIP_BYTES_TO_WORD(
                    (*_sent_msg)[VSOMEIP_SERVICE_POS_MIN],
                    (*_sent_msg)[VSOMEIP_SERVICE_POS_MAX]);
            its_method = VSOMEIP_BYTES_TO_WORD(
                    (*_sent_msg)[VSOMEIP_METHOD_POS_MIN],
                    (*_sent_msg)[VSOMEIP_METHOD_POS_MAX]);
            its_client = VSOMEIP_BYTES_TO_WORD(
                    (*_sent_msg)[VSOMEIP_CLIENT_POS_MIN],
                    (*_sent_msg)[VSOMEIP_CLIENT_POS_MAX]);
            its_session = VSOMEIP_BYTES_TO_WORD(
                    (*_sent_msg)[VSOMEIP_SESSION_POS_MIN],
                    (*_sent_msg)[VSOMEIP_SESSION_POS_MAX]);
        }
        VSOMEIP_WARNING << "tce::send_cbk received error: "
                << _error.message() << " (" << std::dec
                << _error.value() << ") " << get_remote_information()
                << " " << std::dec << queue_.size()
                << " " << std::dec << queue_size_ << " ("
                << std::hex << std::setw(4) << std::setfill('0') << its_client <<"): ["
                << std::hex << std::setw(4) << std::setfill('0') << its_service << "."
                << std::hex << std::setw(4) << std::setfill('0') << its_method << "."
                << std::hex << std::setw(4) << std::setfill('0') << its_session << "]";
    }
}

bool tls_client_endpoint_impl::tp_segmentation_enabled(service_t _service,
                                                       method_t _method) const {
    (void)_service;
    (void)_method;
    return false;
}

std::uint32_t tls_client_endpoint_impl::get_max_allowed_reconnects() const {
    return MAX_RECONNECTS_UNLIMITED;
}

void tls_client_endpoint_impl::max_allowed_reconnects_reached() {
    return;
}

void tls_client_endpoint_impl::wait_until_sent(const boost::system::error_code &_error) {

    std::unique_lock<std::mutex> its_sent_lock(sent_mutex_);
    if (!is_sending_ || !_error) {
        its_sent_lock.unlock();
        if (!_error)
            VSOMEIP_WARNING << __func__
                << ": Maximum wait time for send operation exceeded for tce.";

        std::shared_ptr<endpoint_host> its_ep_host = endpoint_host_.lock();
        its_ep_host->on_disconnect(shared_from_this());
        restart(true);
    } else {
        std::chrono::milliseconds its_timeout(VSOMEIP_MAX_TCP_SENT_WAIT_TIME);
        boost::system::error_code ec;
        sent_timer_.expires_from_now(its_timeout, ec);
        sent_timer_.async_wait(std::bind(&tls_client_endpoint_impl::wait_until_sent,
                std::dynamic_pointer_cast<tls_client_endpoint_impl>(shared_from_this()),
                std::placeholders::_1));
    }
}

void tls_client_endpoint_impl::shutdown_and_close_ssl_socket(bool _recreate_socket) {
    std::unique_lock<std::mutex> its_lock(socket_mutex_);
    shutdown_and_close_ssl_socket_unlocked(_recreate_socket);
}

void tls_client_endpoint_impl::shutdown_and_close_ssl_socket_unlocked(bool _recreate_socket) {
    if (ssl_socket_) {
        boost::system::error_code its_error;
        try {
            ssl_socket_->shutdown(its_error);
        } catch (const boost::system::system_error& e) {
            VSOMEIP_ERROR << "tls_client_endpoint_impl::" << __func__ << ": " << e.what();
        }

        if (ssl_socket_->lowest_layer().is_open()) {
#ifndef _WIN32
            if (-1 == fcntl(ssl_socket_->lowest_layer().native_handle(), F_GETFD)) {
                VSOMEIP_ERROR << "cei::shutdown_and_close_ssl_socket_unlocked: socket/handle closed already '"
                        << std::string(std::strerror(errno))
                        << "' (" << errno << ") " << get_remote_information();
            }
#endif
            ssl_socket_->lowest_layer().shutdown(socket_type::shutdown_both, its_error);
            ssl_socket_->lowest_layer().close(its_error);
        }
    }
    if (_recreate_socket) {
        ssl_socket_.reset(new ssl_socket_t(tcp_client_endpoint_base_impl::service_, ssl_context_));
    }
}

} // namespace vsomeip_v3
