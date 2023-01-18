import ssl
import socket
import logging
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    host = 'greglangford.co.uk'
    port = 443
    expiry_days = 14

    try:
        logger.info(f"Attempting to get certificate for host {host} on port {port}")
        certificate = PeerCertificate(host, port)

        if certificate.match_host():
            logger.info(f"Certificate matches the host {host}")

        if not certificate.is_expiring(days=expiry_days):
            logger.info(f"Certificate for host {host} is not due to expire within {expiry_days} days")
    except PeerCertificateException as e:
        logger.error(e)

class PeerCertificate():
    def __init__(self, host, port):
        
        self.host = host
        self.port = port

        try:
            context = ssl.create_default_context()
            context.check_host = False

            with socket.create_connection((self.host, self.port), timeout=30) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    certificate = ssock.getpeercert()

                    if certificate:
                        self.certificate = certificate

        except socket.timeout:
            raise PeerCertificateException(f"Timeout connecting to {host} on port {port}")
        except ssl.SSLError as e:
            logger.debug(e)
            raise PeerCertificateException(f"No certificate found for host {host} on port {port}")

    def is_expiring(self, days=14):
        """Raise a PeerCertificateException if certificate is expiring within 'days' or return False"""
        try:
            expiry_date = datetime.datetime.strptime(self.certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
            expiry_date_delta = expiry_date - datetime.timedelta(days=days)

            if datetime.datetime.utcnow() >= expiry_date_delta:
                raise PeerCertificateException(f"The certificate for host {self.host} is expiring within {days} days")

        except ValueError as e:
            logger.debug(e)
            raise PeerCertificateException(f"Error parsing attribute 'notAfter' from certificate into datetime")

        return False

    def match_host(self):
        """Match the host to the certificate or throw a PeerCertificateException"""
        try:
            ssl.match_hostname(self.certificate, self.host)
        except ssl.CertificateError as e:
            logger.debug(e)
            raise PeerCertificateException(f"host {self.host} does not match the certificate")

        return True

class PeerCertificateException(Exception):
    pass