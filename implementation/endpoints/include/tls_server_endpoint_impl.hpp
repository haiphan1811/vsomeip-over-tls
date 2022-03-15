// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TLS_SERVER_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_TLS_SERVER_ENDPOINT_IMPL_HPP_

#include <map>
#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <vsomeip/defines.hpp>
#include <vsomeip/export.hpp>
#include "server_endpoint_impl.hpp"

#include <chrono>

namespace vsomeip_v3 {

typedef server_endpoint_impl<
            boost::asio::ip::tcp
        > tls_server_endpoint_base_impl;

class tls_server_endpoint_impl: public tls_server_endpoint_base_impl {

public:
    tls_server_endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                             const std::shared_ptr<routing_host>& _routing_host,
                             const endpoint_type& _local,
                             boost::asio::io_service &_io,
                             const std::shared_ptr<configuration>& _configuration);
    virtual ~tls_server_endpoint_impl();

    void start();
    void stop();

    bool send_to(const std::shared_ptr<endpoint_definition> _target,
                 const byte_t *_data, uint32_t _size);
    bool send_error(const std::shared_ptr<endpoint_definition> _target,
                const byte_t *_data, uint32_t _size);
    void send_queued(const queue_iterator_type _queue_iterator);
    void send_queued_sync(const queue_iterator_type _queue_iterator);
    void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const;

    VSOMEIP_EXPORT bool is_established(const std::shared_ptr<endpoint_definition>& _endpoint);

    bool get_default_target(service_t, endpoint_type &) const;

    std::uint16_t get_local_port() const;
    bool is_reliable() const;
    bool is_local() const;

    // dummies to implement endpoint_impl interface
    // TODO: think about a better design!
    void receive();
    void print_status();
private:
    class ssl_connection: public std::enable_shared_from_this<ssl_connection> {
    public:
        typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_t;
        typedef std::shared_ptr<ssl_connection> ptr;

        static ptr create_ssl_connection(const std::weak_ptr<tls_server_endpoint_impl>& _server,
                                         std::uint32_t _max_message_size,
                                         std::uint32_t _buffer_shrink_threshold,
                                         bool _magic_cookies_enabled,
                                         boost::asio::io_service & _io_service,
                                         std::chrono::milliseconds _send_timeout,
                                         const cfg::tls_credentials& _ssl_credentials);

        socket_type::lowest_layer_type& get_socket();
        std::unique_lock<std::mutex> get_socket_lock();

        void start();
        void stop();
        void receive();

        void send_queued(const queue_iterator_type _queue_iterator);
        void send_queued_sync(const queue_iterator_type _queue_iterator);

        void set_remote_info(const endpoint_type &_remote);
        const std::string get_address_port_remote() const;
        std::size_t get_recv_buffer_capacity() const;

    private:
        ssl_connection(const std::weak_ptr<tls_server_endpoint_impl>& _server,
                       std::uint32_t _max_message_size,
                       std::uint32_t _recv_buffer_size_initial,
                       std::uint32_t _buffer_shrink_threshold,
                       bool _magic_cookies_enabled,
                       boost::asio::io_service & _io_service,
                       std::chrono::milliseconds _send_timeout,
                       const cfg::tls_credentials& _ssl_credentials);

        void handshake_cbk(const boost::system::error_code& _error);
        void receive_cbk(boost::system::error_code const &_error,
                         std::size_t _bytes);
        // TODO: should register user customized passwd callback
        std::string get_password_cbk() const { return "test"; }
        bool send_magic_cookie(message_buffer_ptr_t &_buffer);
        bool is_magic_cookie(size_t _offset) const;
        void calculate_shrink_count();
        const std::string get_address_port_local() const;
        void handle_recv_buffer_exception(const std::exception &_e);
        std::size_t write_completion_condition(
                const boost::system::error_code& _error,
                std::size_t _bytes_transferred, std::size_t _bytes_to_send,
                service_t _service, method_t _method, client_t _client, session_t _session,
                const std::chrono::steady_clock::time_point _start);
        void stop_and_remove_connection();
        void wait_until_sent(const boost::system::error_code &_error);

        std::mutex ssl_socket_mutex_;
        boost::asio::ssl::context ssl_context_;
        std::unique_ptr<ssl_socket_t> ssl_socket_;
        std::weak_ptr<tls_server_endpoint_impl> server_;

        const uint32_t max_message_size_;
        const uint32_t recv_buffer_size_initial_;

        message_buffer_t recv_buffer_;
        size_t recv_buffer_size_;
        std::uint32_t missing_capacity_;
        std::uint32_t shrink_count_;
        const std::uint32_t buffer_shrink_threshold_;

        endpoint_type remote_;
        boost::asio::ip::address remote_address_;
        std::uint16_t remote_port_;
        std::atomic<bool> magic_cookies_enabled_;
        std::chrono::steady_clock::time_point last_cookie_sent_;
        const std::chrono::milliseconds send_timeout_;
        const std::chrono::milliseconds send_timeout_warning_;
    };

    std::mutex acceptor_mutex_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::mutex ssl_connections_mutex_;
    typedef std::map<endpoint_type, ssl_connection::ptr> ssl_connections_t;
    ssl_connections_t ssl_connections_;
    const std::uint32_t buffer_shrink_threshold_;
    const std::uint16_t local_port_;
    const std::chrono::milliseconds send_timeout_;

private:
    void remove_ssl_connection(ssl_connection *_ssl_connection);
    void accept_cbk(const ssl_connection::ptr& _connection,
                    boost::system::error_code const &_error);
    std::string get_remote_information(
            const queue_iterator_type _queue_iterator) const;
    std::string get_remote_information(const endpoint_type& _remote) const;
    bool tp_segmentation_enabled(service_t _service, method_t _method) const;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TLS_SERVER_ENDPOINT_IMPL_HPP_
