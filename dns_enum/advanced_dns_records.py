
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from .console_output import color_print, ConsoleColors
import requests
import dns.message
import dns.rdatatype
import dns.resolver
import dns.query
import httpx
import yaml 
import base64
import socket
import ssl
import certifi
from flask_socketio import SocketIO,emit,join_room
from scripts.utils import get_dynamic_max_workers, stop_event


def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def get_enabled_dns_types(config):
    return [rtype.upper() for rtype, enabled in config.get("dns_types", {}).items() if enabled]

def get_providers_url(config):
    return config.get("dns_providers", {}).get("url",{})

def get_providers_add(config):
    return config.get("dns_providers", {}).get("address",{})

def get_providers_add_ip(config):
    return config.get("dns_providers", {}).get("address",{}).get("ip",{})

def get_providers_add_hostname(config):
    return config.get("dns_providers", {}).get("address",{}).get("hostname",{})

def get_dns_retries(config):
    return config.get("advanced",{}).get("dns_retries", {})  # Default to 3 retries if not specified

def get_dns_timeout(config):
    return config.get("advanced",{}).get("dns_timeout", {})  # Default to 5 seconds if not specified


def extract_from_answer(dns_response: str,dns_type: str) -> list:
    lines = dns_response.splitlines()
    in_answer = False
    answer = []

    for line in lines:
        if line.startswith(";ANSWER"):
            in_answer = True
            continue
        if in_answer:
            if line.startswith(";"):  # end of answer section
                break
            parts = line.split()
            if len(parts) >= 5 and parts[3] in (dns_type):
                answer.append(parts[4])  # Extract the relevant part of the answer
    return answer


def query_advanced_dns_records(domain, verbose=False):
    """
    Query advanced DNS records for a given domain, including SPF, NSEC, NSEC3, DS, DNSKEY, and RRSIG.
    """
    color_print(f"Querying advanced DNS records for {domain}...",ConsoleColors.OKBLUE)

    # List of advanced DNS record types
    advanced_record_types = ["SPF", "NSEC", "NSEC3", "DS", "DNSKEY", "RRSIG"]
    results = {}

    for record_type in advanced_record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
            if verbose:
                color_print(f"{record_type} Records:",ConsoleColors.OKCYAN)
                for rdata in answers:
                    print(f"  {rdata}")
        except Exception as e:
            if verbose:
                color_print(f"Error fetching {record_type} records: {e}",ConsoleColors.FAIL)
            results[record_type] = []

    print(f"Advanced DNS record query completed for {domain}.")
    return results

def dns_over_https(domain,output_file=False,verbose=False):
    """
    Perform DNS over HTTPS (DoH) query for a given domain.
    """
    config = load_config("config.yaml")
    record_types = get_enabled_dns_types(config)
    providers = get_providers_url(config)

    results = {}
    
    for provider_name , doh_url in providers.items():
        
        provider_results = {}
        for record_type in record_types:
            try:
                query = dns.message.make_query(domain, dns.rdatatype.from_text(record_type),want_dnssec=True)
                answers = []
                
                wire = query.to_wire()
                encoded = base64.urlsafe_b64encode(wire).rstrip(b'=').decode()
                
                if type(doh_url) is list:
                    for purl in doh_url:
                        print(purl)
                        url = purl + "?dns=" + encoded
                        print(url)
                        header = {"accept": "application/dns-message"}
                        response = requests.get(url, headers=header)
                        if response.status_code == 200:
                            answers = dns.message.from_wire(response.content).to_text()
                            answers = extract_from_answer(answers, record_type)
                            provider_results[record_type] = answers
                else:
                    url = doh_url + "?dns=" + encoded
                    header = {"accept": "application/dns-message"}
                    response = requests.get(url, headers=header)
                    if response.status_code == 200:
                        answers = dns.message.from_wire(response.content).to_text()
                        answers = extract_from_answer(answers, record_type)
                        provider_results[record_type] = answers
                if answers:
                        if verbose:
                            print(f"[{provider_name}] {record_type} for {domain}: {answers}")
            except Exception as e:
                provider_results[record_type] = []
                if verbose:
                    color_print(f"[{provider_name}] Error {record_type} for {domain}: {e}",ConsoleColors.FAIL)
        results[provider_name] = provider_results
                        
    if output_file:
        with open(output_file, "w") as f:
            f.write(str(results))
    color_print(f"DNS over HTTP probing results saved to {output_file}",ConsoleColors.OKGREEN)
    return results

def dns_over_tls(domain, output_file=False, verbose=False):
    """
    Perform DNS over TLS (DoT) query for a given domain.
    """
    config = load_config("config.yaml")
    record_types = get_enabled_dns_types(config)
    providers= get_providers_add(config)
    providers_ips = get_providers_add_ip(config)
    providers_hostnames = get_providers_add_hostname(config)
    dns_retries = get_dns_retries(config)
    dns_timeout = get_dns_timeout(config)
    port = 853  # Default DoT port
    results = {}
    
    for provider_name,provider_att in providers.items():
        ips = provider_att.get("ip", {})
        hostnames = provider_att.get("hostname", {})
        print(ips, hostnames)
        provider_results = {}
        for record_type in record_types:
            #for provider_add, provider_attr in provider_att.items():
                try:
                    answers=[]
                    query = dns.message.make_query(domain, dns.rdatatype.from_text(record_type))
                    
                    for attempt in range(dns_retries):
                        if type(ips) is list:
                            
                            for ip in ips:
                                try:
                                    print(ip)
                                    sock = socket.create_connection((ip, port), timeout=dns_timeout)
                                    context = ssl.create_default_context(cafile=certifi.where())
                                    tls_sock = context.wrap_socket(sock, server_hostname=hostnames)
                                    # Send query with length prefix
                                    data = query.to_wire()
                                    tls_sock.send(len(data).to_bytes(2, byteorder="big") + data)
                                    # Receive length and response
                                    resp_len = int.from_bytes(tls_sock.recv(2), byteorder="big")
                                    response_data = tls_sock.recv(resp_len)
                                    tls_sock.close()

                                    response = dns.message.from_wire(response_data)
                                    #print(response)
                                    provider_results[record_type] = [rdata.to_text() for rrset in response.answer for rdata in rrset]
                                except Exception as e:
                                    if attempt == dns_retries - 1:
                                        raise e
                        else:
                            #print(ips)
                            for ip in ips:
                                try:
                                    print(ip)
                                    sock = socket.create_connection((ip, port), timeout=dns_timeout)
                                    context = ssl.create_default_context(cafile=certifi.where())    
                                    tls_sock = context.wrap_socket(sock, server_hostname=hostnames)
                                    # Send query with length prefix
                                    data = query.to_wire()
                                    tls_sock.sendall(len(data).to_bytes(2, "big") + data)
                                    # Receive length and response
                                    resp_len = int.from_bytes(tls_sock.recv(2), "big")
                                    response_data = tls_sock.recv(resp_len)
                                    tls_sock.close()

                                    response = dns.message.from_wire(response_data)
                                    #print(response)
                                    provider_results[record_type] = [rdata.to_text() for rrset in response.answer for rdata in rrset]
                                except Exception as e:
                                    if attempt == dns_retries - 1:
                                        raise e
                except Exception as e:
                    provider_results[record_type] = []
                    if verbose:
                        color_print(f"[{provider_name}] Error {record_type} for {domain}: {e}",ConsoleColors.FAIL)
        if provider_results:
            if verbose:
                color_print(f"[{provider_name}] DNS over TLS results for {domain}:", ConsoleColors.OKCYAN)
                for record_type, answers in provider_results.items():
                    print(f"  {record_type}: {answers}")
        
        results[str(provider_name)] = provider_results
        return results
    
    
def dns_over_https_flask(domain, output_file=False, verbose=False):
    """
    Perform DNS over HTTPS (DoH) query for a given domain.
    Emits partial results to enum_update if socketio is provided.
    """
    config = load_config("config.yaml")
    record_types = get_enabled_dns_types(config)
    providers = get_providers_url(config)

    results = {}
    stop_event.clear() 
    for provider_name, doh_url in providers.items():
        provider_results = {}
        for record_type in record_types:
            try:
                if stop_event.is_set():
                    break
                query = dns.message.make_query(domain, dns.rdatatype.from_text(record_type), want_dnssec=True)
                answers = []
                wire = query.to_wire()
                encoded = base64.urlsafe_b64encode(wire).rstrip(b'=').decode()
                if type(doh_url) is list:
                    for purl in doh_url:
                        if stop_event.is_set():
                            break
                        url = purl + "?dns=" + encoded
                        header = {"accept": "application/dns-message"}
                        response = requests.get(url, headers=header)
                        if response.status_code == 200:
                            answers = dns.message.from_wire(response.content).to_text()
                            answers = extract_from_answer(answers, record_type)
                            provider_results[record_type] = answers
                            # Emit partial result
                            
                            emit(
                                    'enum_update',
                                    {
                                        'step': f'DoH-{provider_name}',
                                        'record_type': record_type,
                                        'result': answers
                                    },
                                
                                )
                else:
                    url = doh_url + "?dns=" + encoded
                    header = {"accept": "application/dns-message"}
                    response = requests.get(url, headers=header)
                    if response.status_code == 200:
                        answers = dns.message.from_wire(response.content).to_text()
                        answers = extract_from_answer(answers, record_type)
                        provider_results[record_type] = answers
                        # Emit partial result
                        
                        emit(
                                'enum_update',
                                {
                                    'step': f'DoH-{provider_name}',
                                    'record_type': record_type,
                                    'result': answers
                                },
                                
                        )
                if answers and verbose:
                    print(f"[{provider_name}] {record_type} for {domain}: {answers}")
            except Exception as e:
                provider_results[record_type] = []
                if verbose:
                    color_print(f"[{provider_name}] Error {record_type} for {domain}: {e}", ConsoleColors.FAIL)
        results[provider_name] = provider_results

    # if output_file:
        # with open(output_file, "w") as f:
            # f.write(str(results))
    # if verbose:
        # color_print(f"DNS over HTTP probing results saved to {output_file}", ConsoleColors.OKGREEN)
    return results

def dns_over_tls_flask(domain, output_file=False, verbose=False):
    """
    Perform DNS over TLS (DoT) query for a given domain.
    Emits partial results to enum_update if socketio is provided.
    """
    config = load_config("config.yaml")
    record_types = get_enabled_dns_types(config)
    providers = get_providers_add(config)
    providers_ips = get_providers_add_ip(config)
    providers_hostnames = get_providers_add_hostname(config)
    dns_retries = get_dns_retries(config)
    dns_timeout = get_dns_timeout(config)
    port = 853  # Default DoT port
    results = {}
    
    stop_event.clear()  # Clear the stop event to allow enumeration to proceed
    
    for provider_name, provider_att in providers.items():
        if stop_event.is_set():
            break
        ips = provider_att.get("ip", {})
        hostnames = provider_att.get("hostname", {})
        provider_results = {}
        for record_type in record_types:
            try:
                if stop_event.is_set():
                    break
                answers = []
                query = dns.message.make_query(domain, dns.rdatatype.from_text(record_type))
                for attempt in range(dns_retries):
                    if stop_event.is_set():
                        break
                    if type(ips) is list:
                        for ip in ips:
                            try:
                                if stop_event.is_set():
                                    break
                                sock = socket.create_connection((ip, port), timeout=dns_timeout)
                                context = ssl.create_default_context(cafile=certifi.where())
                                tls_sock = context.wrap_socket(sock, server_hostname=hostnames)
                                data = query.to_wire()
                                tls_sock.send(len(data).to_bytes(2, byteorder="big") + data)
                                resp_len = int.from_bytes(tls_sock.recv(2), byteorder="big")
                                response_data = tls_sock.recv(resp_len)
                                tls_sock.close()
                                response = dns.message.from_wire(response_data)
                                answers = [rdata.to_text() for rrset in response.answer for rdata in rrset]
                                provider_results[record_type] = answers
                                # Emit partial result
                                
                                emit(
                                        'enum_update',
                                        {
                                            'step': f'DoT-{provider_name}',
                                            'record_type': record_type,
                                            'result': answers
                                        },
                                        
                                    )
                            except Exception as e:
                                if attempt == dns_retries - 1:
                                    raise e
                    else:
                        for ip in ips:
                            try:
                                if stop_event.is_set():
                                    break
                                sock = socket.create_connection((ip, port), timeout=dns_timeout)
                                context = ssl.create_default_context(cafile=certifi.where())
                                tls_sock = context.wrap_socket(sock, server_hostname=hostnames)
                                data = query.to_wire()
                                tls_sock.sendall(len(data).to_bytes(2, "big") + data)
                                resp_len = int.from_bytes(tls_sock.recv(2), "big")
                                response_data = tls_sock.recv(resp_len)
                                tls_sock.close()
                                response = dns.message.from_wire(response_data)
                                answers = [rdata.to_text() for rrset in response.answer for rdata in rrset]
                                provider_results[record_type] = answers
                                # Emit partial result
                                
                                emit(
                                        'enum_update',
                                        {
                                            'step': f'DoT-{provider_name}',
                                            'record_type': record_type,
                                            'result': answers
                                        },
                                        
                                    )
                            except Exception as e:
                                if attempt == dns_retries - 1:
                                    raise e
            except Exception as e:
                provider_results[record_type] = []
                if verbose:
                    color_print(f"[{provider_name}] Error {record_type} for {domain}: {e}", ConsoleColors.FAIL)
        if provider_results and verbose:
            color_print(f"[{provider_name}] DNS over TLS results for {domain}:", ConsoleColors.OKCYAN)
            for record_type, answers in provider_results.items():
                print(f"  {record_type}: {answers}")
        results[str(provider_name)] = provider_results
    return results
    
    