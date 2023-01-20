import os
import ssl
import socket
import logging
import datetime
import boto3
import yaml

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    EXPIRY_DAYS = 14
    CONFIG_PARAMETER_NAME = os.getenv('CONFIG_PARAMETER_NAME', 'certificate_checker_hosts')

    hosts = yaml.safe_load(get_config(CONFIG_PARAMETER_NAME))

    for elem in hosts:
        host = elem['host']
        port = elem['port']

        try:
            certificate = PeerCertificate(host, port)

            if not certificate.is_expiring(days=EXPIRY_DAYS):
                expiry_date = certificate.expiry_date.strftime('%b %d %H:%M:%S %Y %Z')
                logger.info(f"Certificate for host {host} on port {port} is not due to expire within {EXPIRY_DAYS} days, expires on {expiry_date}")
        except PeerCertificateException as e:
            logger.error(e)

    return {}

def get_config(parameter_name):
    client = boto3.client('ssm')

    try:
        response = client.get_parameter(
            Name=parameter_name
        )

        return response['Parameter']['Value']
    except ValueError as e:
        raise e

class PeerCertificate():
    def __init__(self, host, port, socket_timeout=30, check_host=True):
        
        self.host = host
        self.port = port

        try:
            context = ssl.create_default_context()
            context.check_host = check_host

            with socket.create_connection((self.host, self.port), timeout=socket_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    certificate = ssock.getpeercert()

                    if certificate:
                        self.certificate = certificate   

        except (socket.error, ssl.SSLError) as e:
            raise PeerCertificateException(f"Error processing certificate for host {self.host} on port {self.port}: {e}")

        try:
            self.expiry_date = datetime.datetime.strptime(self.certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            raise PeerCertificateException(f"Error parsing attribute 'notAfter' from certificate into datetime")

    def days_until_expiry(self):
        """Returns the number of days until the certificate expiry date"""
        # TODO: Create funcion which will return the days until expiry, this could eventually be used as a CloudWatch metric
        pass

    def is_expiring(self, days=14):
        """Raise a PeerCertificateException if certificate is expiring within 'days' or return False"""
        expiry_date_delta = self.expiry_date - datetime.timedelta(days=days)

        if datetime.datetime.utcnow() >= expiry_date_delta:
            raise PeerCertificateException(f"The certificate for host {self.host} is expiring within {days} days")

        return False

class PeerCertificateException(Exception):
    pass