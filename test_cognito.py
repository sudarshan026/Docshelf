import boto3
from dotenv import load_dotenv
import os

load_dotenv()

cognito = boto3.client('cognito-idp', region_name=os.getenv('AWS_REGION'))

# Test signup
try:
    response = cognito.sign_up(
        ClientId=os.getenv('COGNITO_CLIENT_ID'),
        Username='test@example.com',
        Password='Test1234!@#',
        UserAttributes=[
            {'Name': 'email', 'Value': 'test@example.com'},
            {'Name': 'name', 'Value': 'Test User'}
        ]
    )
    print("✓ Signup successful!")
    print(response)
except Exception as e:
    print("✗ Signup failed!")
    print(f"Error: {str(e)}")