import pytest

from checker import app

@pytest.fixture()
def cloudwatch_event():
    """ Generates CloudWatch Event"""
    return {}

def test_lambda_handler(cloudwatch_event, mocker):
    pass