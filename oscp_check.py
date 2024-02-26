#!/usr/bin/env python3
from socket import gaierror, timeout, socket, SOCK_STREAM, AF_INET
from urllib.parse import urlparse
from urllib import request, error
from typing import List, Union, Tuple
from pathlib import Path
from nassl.ssl_client import (
    OpenSslVersionEnum,
    OpenSslVerifyEnum,
    SslClient,
)
from cryptography.x509 import load_pem_x509_certificate, ocsp, ExtensionNotFound
from nassl.cert_chain_verifier import CertificateChainVerificationFailed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509.oid import ExtensionOID
import certifi
import argparse
import csv
import sys
import time

# Constants
path_to_ca_certs = Path(certifi.where())

def get_ocsp_status(host: str, port: int = 443, proxy: Union[None, Tuple[str, int]] = None, request_timeout: float = 3.0) -> List[str]:
    results: List[str] = []
    results.append(f"Host: {host}:{port}")

    try:
        # Get the remote certificate chain
        cert_chain = get_certificate_chain(host, port, proxy=proxy, request_timeout=request_timeout)

        # Extract OCSP URL from leaf certificate
        ocsp_url = extract_ocsp_url(cert_chain)

        # Build OCSP request
        ocsp_request = build_ocsp_request(cert_chain)

        # Send OCSP request to responder and get result
        ocsp_response = get_ocsp_response(ocsp_url, ocsp_request, proxy=proxy, request_timeout=request_timeout)

        # Extract OCSP result from OCSP response
        ocsp_result = extract_ocsp_result(ocsp_response)

        # If successful, display success message
        if "SUCCESSFUL" in ocsp_result:
            results.append("OCSP Check Successful!")

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    results.append(f"OCSP URL: {ocsp_url}")
    results.append(f"{ocsp_result}")

    return results


def get_certificate_chain(host: str, port: int = 443, proxy: Union[None, Tuple[str, int]] = None, request_timeout: float = 3.0) -> List[str]:
    cert_chain: list = []

    soc = socket(AF_INET, SOCK_STREAM, proto=0)
    soc.settimeout(request_timeout)

    try:
        if proxy is not None: 
            http_proxy_connect((host, port), proxy=proxy, soc=soc)
        else: 
            soc.connect((host, port))

    except (gaierror, timeout, ConnectionRefusedError, IOError, OSError) as err:
        raise Exception(f"Initial Connection Error: {str(err)}")

    ssl_client = SslClient(
        ssl_version=OpenSslVersionEnum.SSLV23,
        underlying_socket=soc,
        ssl_verify=OpenSslVerifyEnum.NONE,
        ssl_verify_locations=path_to_ca_certs,
    )

    ssl_client.set_tlsext_host_name(host)

    try:
        ssl_client.do_handshake()
        cert_chain = ssl_client.get_verified_chain()

    except (IOError, CertificateChainVerificationFailed, ExtensionNotFound) as err:
        raise Exception(f"Certificate Chain Error: {str(err)}")

    except Exception as err:
        raise Exception(f"SSL Handshake Error: {str(err)}")

    finally:
        ssl_client.shutdown()

    return cert_chain


def extract_ocsp_url(cert_chain: List[str]) -> str:
    certificate = load_pem_x509_certificate(str.encode(cert_chain[0]), default_backend())

    try:
        aia_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        for aia_method in iter(aia_extension):
            if aia_method.access_method._name == "OCSP":
                return aia_method.access_location.value

        raise Exception("OCSP URL missing from Certificate AIA Extension.")

    except ExtensionNotFound:
        raise Exception("Certificate AIA Extension Missing. Possible MITM Proxy.")


def build_ocsp_request(cert_chain: List[str]) -> bytes:
    try:
        leaf_cert = load_pem_x509_certificate(str.encode(cert_chain[0]), default_backend())
        issuer_cert = load_pem_x509_certificate(str.encode(cert_chain[1]), default_backend())

    except ValueError:
        raise Exception("Unable to load x509 certificate.")

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, SHA1())
    ocsp_data = builder.build()
    return ocsp_data.public_bytes(serialization.Encoding.DER)


def get_ocsp_response(ocsp_url: str, ocsp_request_data: bytes, proxy: Union[None, Tuple[str, int]] = None, request_timeout: float = 3.0):
    try:
        ocsp_request = request.Request(
            ocsp_url,
            data=ocsp_request_data,
            headers={"Content-Type": "application/ocsp-request"},
        )

        if proxy is not None:
            host, port = proxy
            ocsp_request.set_proxy(f'{host}:{port}', 'http')

        with request.urlopen(ocsp_request, timeout=request_timeout) as resp:
            return resp.read()

    except error.URLError as err:
        raise Exception(f"OCSP Responder Connection Error: {str(err)}")

    except ValueError as err:
        raise Exception(f"OCSP Responder Connection Error: {str(err)}")


def extract_ocsp_result(ocsp_response):
    try:
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response)

        if str(ocsp_response.response_status.value) != "0":
            ocsp_response = str(ocsp_response.response_status)
            ocsp_response = ocsp_response.split(".")
            raise Exception(f"OCSP Request Error: {ocsp_response[1]}")

        certificate_status = str(ocsp_response.certificate_status)
        certificate_status = certificate_status.split(".")
        return f"OCSP Status: {certificate_status[1]}"

    except ValueError as err:
        return f"OCSP Result Error: {str(err)}"

def main():
    parser = argparse.ArgumentParser(description="Check the OCSP revocation status for x509 digital certificates.")
    parser.add_argument("--input", "-i", metavar="input", type=str, required=True, help="File containing target hosts, one per line")
    parser.add_argument("--output", "-o", metavar="output", type=str, required=True, help="Output CSV file")
    parser.add_argument("--port", "-p", metavar="port", type=int, required=False, default=443, help="Default port to test (default is 443)")

    args = parser.parse_args()

    with open(args.input, 'r') as input_file, open(args.output, 'w', newline='') as output_file:
        csv_writer = csv.writer(output_file)
        csv_writer.writerow(["Host", "OCSP URL", "OCSP Status"])

        total_targets = len(input_file.readlines())
        input_file.seek(0)  # Reset file cursor to the beginning for reading again

        for i, target in enumerate(input_file.readlines(), start=1):
            target = target.strip()
            
            # Check if the target includes a custom port
            if ":" in target:
                host, custom_port = target.split(":")
                port = int(custom_port)
            else:
                host = target
                port = args.port

            # Display countdown progress
            progress = (i / total_targets) * 100
            sys.stdout.write(f"\rChecking {i}/{total_targets}: {host}:{port} [{int(progress)}% complete] {' ' * 20}")
            sys.stdout.flush()

            ocsp_status = get_ocsp_status(host, port)
            
            # Check if the OCSP result has at least 3 elements before accessing index 2
            if len(ocsp_status) >= 3:
                csv_writer.writerow([host, ocsp_status[1], ocsp_status[2]])
            else:
                csv_writer.writerow([host, "timeout", ""])

        # Print completion message
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.write("OCSP Check Completed!\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
