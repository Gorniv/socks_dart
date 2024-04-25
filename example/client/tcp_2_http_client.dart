import 'dart:convert';
import 'dart:io';

import 'package:socks5_proxy/socks_client.dart';

void main() async {
// Create HttpClient object
final client = HttpClient();

// Assign connection factory
SocksTCPClient.assignToHttpClient(client, [
  ProxySettings(InternetAddress.loopbackIPv4, 1080),
]);

// GET request
final request = await client.getUrl(Uri.parse('http://example.com/'));
final response = await request.close();
// Print response
print(await utf8.decodeStream(response));
// Close client
client.close();
}
