# aws-lambda-certificate-checker
AWS Lambda function written in Python which will check if a certificate for a hostname is due to expire within a defined number of days

### Building
sam build

### Running
sam local invoke -e events/event.json