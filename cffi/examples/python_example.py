#!/usr/bin/env python3
"""
AzureTLS Python Example using ctypes

This example demonstrates how to use the AzureTLS CFFI library from Python.
"""

import json

from azuretls import AzureTLSSession


def main():
    """Example usage"""
    print("AzureTLS Python Example")
    print("=" * 40)

    # Create session with configuration
    config = {
        "browser": "chrome",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "timeout_ms": 30000,
        "max_redirects": 10,
    }

    try:
        with AzureTLSSession(config) as session:
            # Example 1: Simple GET request
            print("\n1. Simple GET request:")
            response = session.get("https://fp.impersonate.pro/api/http3")
            if response.error:
                print(f"Error: {response.error}")
            else:
                print(f"Status: {response.status_code}")
                print(f"Protocol: {response.protocol}")
                print(f"URL: {response.url}")
                if response.text:
                    body_json = response.json()
                    print(
                        f"User-Agent: {body_json.get('headers', {}).get('User-Agent', 'N/A')}"
                    )

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

            http2_fp = "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"
            session.apply_http2(http2_fp)
            ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
            session.apply_ja3(
                ja3,
                "chrome",
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
            except Exception as e:
                print(f"HTTP/2 error: {e}")

            print("\n5. Using proxy:")
            try:
                session.set_proxy("http://localhost:8083")
                response = session.get("https://httpbin.org/ip")
                print(f"IP with proxy: {response.text}")
            except Exception as e:
                print(f"Proxy error: {e}")
            print("text", session.get("https://httpbin.org/cookies/set/a/b").text)
            print(session.get("https://httpbin.org/get", no_cookie=True).text)
            print(
                session.get(
                    "https://httpbin.org/get",
                    no_cookie=True,
                    headers={"Cookie": ["q=1", "q=2", "q=3"]},
                ).text
            )

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

            print("\nExample completed successfully!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
