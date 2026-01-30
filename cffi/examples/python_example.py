#!/usr/bin/env python3
"""
AzureTLS Python Example using ctypes

This example demonstrates how to use the AzureTLS CFFI library from Python.
"""

import json

from azuretls import AzureTLSSession, AzureTLSWebsocket


def main():
    """Example usage"""
    print("AzureTLS Python Example")
    print("=" * 40)

    # Create session with configuration
    config = {
        "browser": "firefox",
        "timeout_ms": 30000,
        "max_redirects": 10,
        "insecure_skip_verify": True,
    }

    try:
        with AzureTLSSession(config) as session:
            http2_fp = "1:4096;2:1;3:100;4:2097152;5:16384;6:4294967295|15663105|0|m,s,p,a"
            session.apply_http2(http2_fp)
            ja3 = "771,4866-4865-4867-49196-49200-49195-52393-49199-52392-49162-49161-49172-49171,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0"
            session.apply_ja3(
                ja3,
                "firefox",
                {
                    "alpn_protocols": ["h2", "http/1.1"],
                    "signature_algorithms": [
                        1027,
                        2052,
                        1025,
                        1283,
                        2053,
                        2053,
                        1281,
                        2054,
                        1537,
                        513,
                    ],
                    "supported_versions": [0x0A0A, 772, 771],
                    "cert_compression_algos": [1],
                    "delegated_credentials_algorithm_signatures": [],
                    "psk_key_exchange_modes": [1],
                    "signature_algorithms_cert": [
                        1027,
                        2052,
                        1025,
                        1283,
                        2053,
                        2053,
                        1281,
                        2054,
                        1537,
                        513,
                    ],
                    "application_settings_protocols": ["h2"],
                    "renegotiation_support": 1,
                    "record_size_limit": 0,
                },
            )
            # Example 1: Simple GET request
            print("\n1. Simple GET request:")
            response = session.get("https://api.ipify.org")
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                print(f"Protocol: {response.protocol}")
                print(f"URL: {response.url}")

            # Example 2: POST request with JSON body
            print("\n2. POST request with JSON:")
            post_data = json.dumps({"message": "Hello from AzureTLS Python!"})
            response = session.post(
                "https://httpbin.org/post",
                body=post_data,
                headers={"Content-Type": "application/json"},
            )
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                print(f"Protocol: {response.protocol}")
                if response.text:
                    body_json = json.loads(response.text)
                    print(f"Received data: {body_json.get('json', {})}")

            # Example 3: JA3 fingerprinting
            print("\n3. Applying JA3 fingerprint:")
            try:
                response = session.get("https://tls.peet.ws/api/all")
                if response.error:
                    print(f"Error: {response.error}")
                else:
                    print(
                        f"TLS fingerprint test status: {response.json()['tls']['ja3'] == ja3}"
                    )
            except Exception as e:
                print(f"JA3 error: {e}")

            # Example 4: HTTP/2 fingerprinting
            print("\n4. Applying HTTP/2 fingerprint:")
            try:
                print(
                    "HTTP/2 fingerprint apply status:",
                    response.json()["http2"]["akamai_fingerprint"] == http2_fp,
                )
                print(response.json()["http2"]["akamai_fingerprint"])
                print(http2_fp)
            except Exception as e:
                print(f"HTTP/2 error: {e}")

            print("\n5. Using proxy:")
            try:
                session.set_proxy("http://localhost:8083")
                response = session.get("https://httpbin.org/ip")
                print(f"IP with proxy: {response.text}")
            except Exception as e:
                print(f"Proxy error: {e}")

            # Example 7: Get cookies
            print("\n7. Cookie management:")
            try:
                # Make a request that sets cookies
                response = session.get(
                    "https://tls.peet.ws/api/all",
                    headers={"Cookie": ["yarrak=1", "yarrak2=2"]},
                )

            except Exception as e:
                print(f"Cookie error: {e}")

            print("\n8. Websocket")
            try:
                ws = AzureTLSWebsocket(
                    session.session_id,
                    "wss://premws-pt1.365lpodds.com/zap/?uid=8704747766393455",
                    headers={
                        "Host": None,
                        "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                        "sec-ch-ua-mobile": "?0",
                        "sec-ch-ua-platform": '"macOS"',
                        "Upgrade-Insecure-Requests": "1",
                        "User-Agent": "Mozilla (Linux; Android 12 Phone; CPU M2003J15SC OS 12 like Gecko) Chrome/141.0.7390.122 Gen6 bet365/8.0.14.00",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-User": "?1",
                        "Sec-Fetch-Dest": "document",
                        "Accept-Encoding": "gzip, deflate, br, zstd",
                        "Accept-Language": "tr-TR,tr;q=0.9",
                        "Priority": "u=0, i",
                        "Pragma": "no-cache",
                        "Cache-Control": "no-cache",
                        "Origin": "https://www.bet365.com",
                        "Sec-GPC": "1",
                    },
                    enable_compression=True,
                    read_buffer_size=1024,
                    write_buffer_size=1024,
                    subprotocols=["zap-protocol-v2"],
                )
                while True:
                    message, type = ws.recv()
                    print(message, type)
            except Exception as e:
                print("WS Error:", e)

            print("\nExample completed successfully!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
