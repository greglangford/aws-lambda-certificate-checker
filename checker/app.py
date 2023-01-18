import ssl
import socket
import logging
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    hostname = '1.2.3.4'
    port = 443
    expiry_days = 14

    try:
        logger.info(f"Attempting to get certificate for hostname {hostname} on port {port}")
        certificate = PeerCertificate(hostname, port)

        if certificate.match_hostname():
            logger.info(f"Certificate matches the hostname {hostname}")

        if not certificate.is_expiring(days=expiry_days):
            logger.info(f"Certificate for hostname {hostname} is not due to expire within {expiry_days} days")
    except PeerCertificateException as e:
        logger.error(e)

class PeerCertificate():
    def __init__(self, hostname, port):
        
        self.hostname = hostname
        self.port = port

        try:
            context = ssl.create_default_context()
            context.check_hostname = False

            with socket.create_connection((self.hostname, self.port), timeout=30) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    certificate = ssock.getpeercert()

                    if certificate:
                        self.certificate = certificate

        except socket.timeout:
            raise PeerCertificateException(f"Time out connecting to {hostname} on port {port}")
        except ssl.SSLError as e:
            logger.debug(e)
            raise PeerCertificateException(f"No certificate found for hostname {hostname} on port {port}")

    def is_expiring(self, days=14):
        """Raise a PeerCertificateException if certificate is expiring within 'days' or return False"""
        try:
            expiry_date = datetime.datetime.strptime(self.certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
            expiry_date_delta = expiry_date - datetime.timedelta(days=days)

            if datetime.datetime.utcnow() >= expiry_date_delta:
                raise PeerCertificateException(f"The certificate for hostname {self.hostname} is expiring within {days} days")

        except ValueError as e:
            logger.debug(e)
            raise PeerCertificateException(f"Error parsing attribute 'notAfter' from certificate into datetime")

        return False

    def match_hostname(self):
        """Match the hostname to the certificate or throw a PeerCertificateException"""
        try:
            ssl.match_hostname(self.certificate, self.hostname)
        except ssl.CertificateError as e:
            logger.debug(e)
            raise PeerCertificateException(f"Hostname {self.hostname} does not match the certificate")

        return True

class PeerCertificateException(Exception):
    pass