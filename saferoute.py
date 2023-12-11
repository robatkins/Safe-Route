import socket
import ssl
import threading
import select
import logging
import time
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(filename='proxy.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set the maximum cache size and cache timeout in seconds
MAX_CACHE_SIZE = 100
CACHE_TIMEOUT = 300  # 5 minutes

# Set blacklisted domains
blacklisted_domains = {'blocked-domain.com', 'example.org'}

# In-memory cache dictionary
cache = {}

def is_blacklisted(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    return domain in blacklisted_domains

def is_cached(url):
    return url in cache and time.time() - cache[url]['timestamp'] < CACHE_TIMEOUT

def cache_resource(url, content):
    if len(cache) >= MAX_CACHE_SIZE:
        # Remove the oldest entry if the cache is full
        oldest_url = min(cache, key=lambda k: cache[k]['timestamp'])
        del cache[oldest_url]

    # Add the new entry to the cache
    cache[url] = {'content': content, 'timestamp': time.time()}

def handle_client(client_socket, target_host, target_port):
    try:
        # receive data from the client
        request = client_socket.recv(4096)

        # Extract the requested URL
        url = request.decode('utf-8').split('\n')[0].split(' ')[1]

        # Check if the URL is blacklisted
        if is_blacklisted(url):
            logging.warning(f"Blocked request to blacklisted domain: {url}")
            return

        # Check if the resource is in the cache and not expired
        if is_cached(url):
            # Serve the cached content to the client
            logging.info(f"Serving cached content for: {url}")
            client_socket.send(cache[url]['content'])
            return

        # forward the request to the target server
        with socket.create_connection((target_host, target_port)) as target_socket:
            target_socket.send(request)

            # receive data from the target server
            response = target_socket.recv(4096)

            # Cache the response if it is cacheable
            if 'Content-Type: text/html' in response.decode('utf-8'):
                cache_resource(url, response)

            # send the response back to the client
            client_socket.send(response)

            # Log the request and response information
            logging.info(f"Request from {client_socket.getpeername()} to {target_host}:{target_port}")
            logging.info(f"Request:\n{request.decode('utf-8').strip()}")
            logging.info(f"Response:\n{response.decode('utf-8').strip()}")

    except socket.error as se:
        logging.error(f"Socket error: {se}")
    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error: {ssl_error}")
    except Exception as e:
        # Log any exceptions that occur
        logging.error(f"Error handling client request: {e}")
    finally:
        # Close the client socket
        client_socket.close()

def handle_https_client(client_socket, target_host, target_port):
    try:
        # wrap the client socket with SSL
        ssl_client_socket = ssl.wrap_socket(client_socket, server_side=False, keyfile=None, certfile=None, ssl_version=ssl.PROTOCOL_SSLv23)

        # receive data from the client
        request = ssl_client_socket.recv(4096)

        # Extract the requested URL
        url = request.decode('utf-8').split('\n')[0].split(' ')[1]

        # Check if the URL is blacklisted
        if is_blacklisted(url):
            logging.warning(f"Blocked HTTPS request to blacklisted domain: {url}")
            return

        # Check if the resource is in the cache and not expired
        if is_cached(url):
            # Serve the cached content to the client
            logging.info(f"Serving cached content for: {url}")
            ssl_client_socket.send(cache[url]['content'])
            return

        # forward the request to the target server
        with socket.create_connection((target_host, target_port)) as target_socket:
            target_socket.send(request)

            # receive data from the target server
            response = target_socket.recv(4096)

            # Cache the response if it is cacheable
            if 'Content-Type: text/html' in response.decode('utf-8'):
                cache_resource(url, response)

            # send the response back to the client
            ssl_client_socket.send(response)

            # Log the request and response information
            logging.info(f"HTTPS Request from {ssl_client_socket.getpeername()} to {target_host}:{target_port}")
            logging.info(f"Request:\n{request.decode('utf-8').strip()}")
            logging.info(f"Response:\n{response.decode('utf-8').strip()}")

    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error: {ssl_error}")
    except Exception as e:
        # Log any exceptions that occur
        logging.error(f"Error handling HTTPS client request: {e}")
    finally:
        # Close the SSL client socket
        ssl_client_socket.close()

def start_proxy_server(bind_host, bind_port, target_host, target_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_host, bind_port))
    server.listen(5)

    print(f'[*] Proxy server listening on {bind_host}:{bind_port}')

    while True:
        try:
            client_socket, addr = server.accept()
            print(f'[*] Accepted connection from: {addr[0]}:{addr[1]}')

            # try to determine whether the connection is HTTP or HTTPS
            first_data = client_socket.recv(1024, socket.MSG_PEEK)
            if b'CONNECT' in first_data:
                # handle HTTPS connection
                client_handler = threading.Thread(
                    target=handle_https_client,
                    args=(client_socket, target_host, target_port)
                )
            else:
                # handle HTTP connection
                client_handler = threading.Thread(
                    target=handle_client,
                    args=(client_socket, target_host, target_port)
                )

            client_handler.start()
        except socket.error as se:
            logging.error(f"Error accepting connection: {se}")

if __name__ == '__main__':
    # Set the target host and port
    target_host = 'www.example.com'
    target_port = 443  # for HTTPS

    # Set the proxy server's listening host and port
    proxy_host = '127.0.0.1'
    proxy_port = 8888

    start_proxy_server(proxy_host, proxy_port, target_host, target_port)

