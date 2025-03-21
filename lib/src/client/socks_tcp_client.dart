import 'dart:io';

import '../enums/socks_connection_type.dart';
import '../shared/proxy_settings.dart';
import 'socks_client.dart';

/// [Socket] wrapper for socks TCP connection.
class SocksTCPClient extends SocksSocket {
  SocksTCPClient._internal(Socket socket)
    : super.protected(socket, SocksConnectionType.connect);

  /// Assign http client connection factory to proxy connection.
  static void assignToHttpClient(
    HttpClient httpClient,
    List<ProxySettings> proxies,
  ) => assignToHttpClientWithSecureOptions(httpClient, proxies);

  /// Assign http client connection factory to proxy connection.
  ///
  /// Applies [host], [context], [onBadCertificate],
  /// [keyLog] and [supportedProtocols] to [SecureSocket] if
  /// connection is tls-over-http
  ///
  /// Set [remoteDnsResolution] to true to resolve hostnames through the SOCKS proxy
  /// instead of locally (similar to curl's socks5h:// mode)
  static void assignToHttpClientWithSecureOptions(
    HttpClient httpClient,
    List<ProxySettings> proxies, {
    dynamic host,
    SecurityContext? context,
    bool Function(X509Certificate certificate)? onBadCertificate,
    void Function(String line)? keyLog,
    List<String>? supportedProtocols,
    bool remoteDnsResolution = false,
    bool resolveProxyHostname = true,
  }) {
    httpClient.connectionFactory = (uri, proxyHost, proxyPort) async {
      // Копируем список прокси, чтобы не менять исходный
      final resolvedProxies = List<ProxySettings>.from(proxies);

      // Если нужно разрешать доменные имена прокси в IP-адреса
      if (resolveProxyHostname) {
        // Разрешаем все прокси последовательно
        for (var i = 0; i < resolvedProxies.length; i++) {
          resolvedProxies[i] = await _resolveProxyHost(resolvedProxies[i]);
        }
      }

      // Determine how to handle the URI host
      if (remoteDnsResolution) {
        // For remote DNS resolution, we use domain type and hostname directly
        // Returns instance of SocksSocket which implements Socket
        final client = connectWithRemoteDns(
          resolvedProxies,
          uri.host, // Use hostname directly instead of resolving to IP
          uri.port,
        );

        // Secure connection after establishing Socks connection
        if (uri.scheme == 'https') {
          final Future<SecureSocket> secureClient;
          return ConnectionTask.fromSocket(
            secureClient = (await client).secure(
              uri.host,
              context: context,
              onBadCertificate: onBadCertificate,
              keyLog: keyLog,
              supportedProtocols: supportedProtocols,
            ),
            () async => (await secureClient).close().ignore(),
          );
        }

        // SocketConnectionTask implements ConnectionTask<Socket>
        return ConnectionTask.fromSocket(
          client,
          () async => (await client).close().ignore(),
        );
      } else {
        // Original behavior - resolve IP locally
        InternetAddress address;
        try {
          // Try to resolve the hostname to IP address
          final addresses = await InternetAddress.lookup(
            uri.host,
          ).timeout(const Duration(seconds: 30));
          if (addresses.isEmpty) {
            throw Exception('Failed to resolve ${uri.host}');
          }
          address = addresses.first;
        } catch (e) {
          // If resolution fails, create a dummy address
          address = InternetAddress(uri.host, type: InternetAddressType.unix);
        }

        // Returns instance of SocksSocket which implements Socket
        final client = connect(resolvedProxies, address, uri.port);

        // Secure connection after establishing Socks connection
        if (uri.scheme == 'https') {
          final Future<SecureSocket> secureClient;
          return ConnectionTask.fromSocket(
            secureClient = (await client).secure(
              uri.host,
              context: context,
              onBadCertificate: onBadCertificate,
              keyLog: keyLog,
              supportedProtocols: supportedProtocols,
            ),
            () async => (await secureClient).close().ignore(),
          );
        }

        // SocketConnectionTask implements ConnectionTask<Socket>
        return ConnectionTask.fromSocket(
          client,
          () async => (await client).close().ignore(),
        );
      }
    };
  }

  /// Check if a string is an IP address
  static bool _isIpAddress(String host) {
    try {
      // Try to parse as IPv4
      final parts = host.split('.');
      if (parts.length != 4) {
        return false;
      }

      for (final part in parts) {
        final num = int.tryParse(part);
        if (num == null || num < 0 || num > 255) {
          return false;
        }
      }

      return true;
    } catch (_) {
      return false;
    }
  }

  /// Resolve proxy hostname to IP address
  static Future<ProxySettings> _resolveProxyHost(ProxySettings proxy) async {
    if (_isIpAddress(proxy.host.address)) {
      return proxy; // If it's already an IP address, keep it as is
    }

    try {
      final addresses = await InternetAddress.lookup(
        proxy.host.address,
      ).timeout(const Duration(seconds: 30));
      if (addresses.isNotEmpty) {
        // Create a new ProxySettings with IP address instead of hostname
        return ProxySettings(
          addresses.first,
          proxy.port,
          username: proxy.username,
          password: proxy.password,
        );
      }
    } catch (e) {
      print('Failed to resolve proxy hostname ${proxy.host}: $e');
    }

    return proxy; // Return original proxy if resolution failed
  }

  /// Connects proxy client to given [proxies] with exit point of [host]\:[port].
  static Future<SocksSocket> connect(
    List<ProxySettings> proxies,
    InternetAddress host,
    int port,
  ) async {
    final client = await SocksSocket.initialize(
      proxies,
      host,
      port,
      SocksConnectionType.connect,
    );
    return client.socket;
  }

  /// Connects proxy client to given [proxies] with exit point of [hostname]\:[port].
  /// Uses remote DNS resolution through the SOCKS proxy.
  static Future<SocksSocket> connectWithRemoteDns(
    List<ProxySettings> proxies,
    String hostname,
    int port,
  ) async {
    final client = await SocksSocket.initializeWithDomain(
      proxies,
      hostname,
      port,
      SocksConnectionType.connect,
    );
    return client.socket;
  }
}
