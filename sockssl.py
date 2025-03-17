import socket
import ssl
from OpenSSL import SSL

def verify_ssl_certificate(hostname, port=443):
    # Create a default context for SSL connections
    context = ssl.create_default_context()
    
    # Establish a connection to the server
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    try:
        # Connect to the server (this initiates the SSL handshake)
        connection.connect((hostname, port))

        # Retrieve the certificate
        cert = connection.getpeercert()

        print("Certificate retrieved successfully.")
        print("Certificate subject:", cert.get('subject'))
        print("Certificate issuer:", cert.get('issuer'))

        # You can further inspect the certificate and verify if it matches certain criteria
        # For example, checking the expiration date
        from datetime import datetime
        not_after = cert['notAfter']
        expiration_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        print("Certificate expiration date:", expiration_date)

        if expiration_date < datetime.utcnow():
            print("Warning: The certificate has expired!")

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Always close the connection
        connection.close()

# Example usage
verify_ssl_certificate("www.example.com")
