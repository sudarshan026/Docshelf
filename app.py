from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import boto3
from botocore.exceptions import ClientError
import os
import uuid
from datetime import datetime
from functools import wraps
import hashlib
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '4f8d7a6b9c1e2f3a8d7e6c5b1a9d8f7e')

# Configure CORS properly
CORS(app, 
     supports_credentials=True,
     origins=['http://localhost:5000', 'http://127.0.0.1:5000'],
     allow_headers=['Content-Type'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
)

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
S3_BUCKET = os.environ.get('S3_BUCKET_NAME', 'docshelf-documents-bucket-unique-name')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'DocShelfDocuments')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', 'us-east-1_phe1PrgWn')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '2po0lhhvkeaf959p7vs10k53cd')

# Debug: Print configuration (remove in production)
print("=" * 50)
print("DocShelf Configuration:")
print(f"AWS Region: {AWS_REGION}")
print(f"S3 Bucket: {S3_BUCKET}")
print(f"DynamoDB Table: {DYNAMODB_TABLE}")
print(f"Cognito Pool ID: {COGNITO_USER_POOL_ID[:20]}..." if COGNITO_USER_POOL_ID else "Cognito Pool ID: NOT SET")
print(f"Cognito Client ID: {COGNITO_CLIENT_ID[:20]}..." if COGNITO_CLIENT_ID else "Cognito Client ID: NOT SET")
print("=" * 50)

# Check if required environment variables are set
if not S3_BUCKET:
    print("WARNING: S3_BUCKET_NAME not set in .env file")
if not COGNITO_USER_POOL_ID:
    print("WARNING: COGNITO_USER_POOL_ID not set in .env file")
if not COGNITO_CLIENT_ID:
    print("WARNING: COGNITO_CLIENT_ID not set in .env file")

# AWS Clients
try:
    s3_client = boto3.client('s3', region_name=AWS_REGION)
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)
    table = dynamodb.Table(DYNAMODB_TABLE)
    print("✓ AWS clients initialized successfully")
except Exception as e:
    print(f"✗ Error initializing AWS clients: {str(e)}")
    print("Make sure AWS CLI is configured: aws configure")

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'xlsx', 'xls', 'ppt', 'pptx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        print("=== Signup Request Received ===")
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data:
            print("Error: No data received")
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        name = data.get('name', '')

        print(f"Email: {email}, Name: {name}")

        if not email or not password:
            print("Error: Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400

        # Check Cognito configuration
        if not COGNITO_CLIENT_ID:
            print("Error: COGNITO_CLIENT_ID not set")
            return jsonify({'error': 'Server configuration error: Cognito not configured'}), 500

        print(f"Attempting signup with ClientId: {COGNITO_CLIENT_ID[:10]}...")

        response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': name}
            ]
        )

        print("✓ Signup successful!")
        print(f"UserSub: {response['UserSub']}")

        return jsonify({
            'message': 'User registered successfully. Please check your email for verification code.',
            'userId': response['UserSub']
        }), 201

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"✗ Cognito error: {error_code}")
        print(f"Message: {error_message}")
        
        if error_code == 'UsernameExistsException':
            return jsonify({'error': 'An account with this email already exists'}), 400
        elif error_code == 'InvalidPasswordException':
            return jsonify({'error': 'Password does not meet requirements. Must be at least 8 characters with uppercase, lowercase, number, and symbol'}), 400
        elif error_code == 'InvalidParameterException':
            return jsonify({'error': f'Invalid parameter: {error_message}'}), 400
        else:
            return jsonify({'error': f'Registration failed: {error_message}'}), 400
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/confirm', methods=['POST'])
def confirm_signup():
    try:
        data = request.json
        email = data.get('email')
        code = data.get('code')

        cognito_client.confirm_sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=email,
            ConfirmationCode=code
        )

        return jsonify({'message': 'Email verified successfully'}), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        print(f"Attempting login for: {email}")  # Debug log

        # Check if Cognito is configured
        if not COGNITO_CLIENT_ID or not COGNITO_USER_POOL_ID:
            return jsonify({'error': 'Cognito not configured. Check .env file'}), 500

        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )

        # Get user attributes
        user_response = cognito_client.get_user(
            AccessToken=response['AuthenticationResult']['AccessToken']
        )

        user_id = user_response['Username']
        
        session['user_id'] = user_id
        session['access_token'] = response['AuthenticationResult']['AccessToken']
        session['email'] = email

        print(f"Login successful for: {email}")  # Debug log

        return jsonify({
            'message': 'Login successful',
            'userId': user_id,
            'accessToken': response['AuthenticationResult']['AccessToken'],
            'idToken': response['AuthenticationResult']['IdToken'],
            'refreshToken': response['AuthenticationResult']['RefreshToken']
        }), 200

    except ClientError as e:
        error_code = e.response['Error']['Code']
        print(f"Cognito error: {error_code} - {str(e)}")  # Debug log
        
        if error_code == 'UserNotFoundException':
            return jsonify({'error': 'User not found'}), 401
        elif error_code == 'NotAuthorizedException':
            return jsonify({'error': 'Invalid email or password'}), 401
        elif error_code == 'UserNotConfirmedException':
            return jsonify({'error': 'Email not verified. Check your email for verification code'}), 401
        else:
            return jsonify({'error': f'Authentication failed: {error_code}'}), 401
    except Exception as e:
        print(f"Unexpected error: {str(e)}")  # Debug log
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    try:
        if 'access_token' in session:
            cognito_client.global_sign_out(
                AccessToken=session['access_token']
            )
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        session.clear()
        return jsonify({'message': 'Logged out'}), 200

# Document Management Routes
@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    try:
        # 1️⃣ Check for file in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed. Allowed: {ALLOWED_EXTENSIONS}'}), 400

        # 2️⃣ Check S3 bucket configuration
        if not S3_BUCKET:
            return jsonify({'error': 'Server misconfiguration: S3 bucket not set'}), 500

        # 3️⃣ Generate document ID and S3 key
        document_id = str(uuid.uuid4())
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        s3_key = f"{user_id}/{document_id}.{file_extension}"

        # 4️⃣ Get file size BEFORE uploading
        file.seek(0, 2)  # move pointer to end
        file_size = file.tell()
        file.seek(0)     # reset pointer to start

        # 5️⃣ Upload file to S3
        try:
            s3_client.upload_fileobj(
                file,
                S3_BUCKET,
                s3_key,
                ExtraArgs={'ContentType': file.content_type}
            )
        except ClientError as e:
            print(f"S3 Upload Error: {str(e)}")
            return jsonify({'error': 'Failed to upload file to S3', 'details': str(e)}), 500

        # 6️⃣ Prepare metadata for DynamoDB
        tags = request.form.get('tags', '')
        metadata = {
            'userId': user_id,
            'documentId': document_id,
            'fileName': filename,
            'fileSize': file_size,
            'fileType': file_extension,
            'contentType': file.content_type,
            's3Key': s3_key,
            'uploadDate': datetime.utcnow().isoformat(),
            'tags': [t.strip() for t in tags.split(',')] if tags else [],
            'description': request.form.get('description', '')
        }

        # 7️⃣ Store metadata in DynamoDB
        try:
            table.put_item(Item=metadata)
        except ClientError as e:
            print(f"DynamoDB Error: {str(e)}")
            # Rollback S3 upload if DynamoDB fails
            try:
                s3_client.delete_object(Bucket=S3_BUCKET, Key=s3_key)
            except Exception:
                pass
            return jsonify({'error': 'Failed to save document metadata', 'details': str(e)}), 500

        return jsonify({
            'message': 'Document uploaded successfully',
            'document': metadata
        }), 201

    except Exception as e:
        import traceback
        traceback.print_exc()  # Print full error in console
        return jsonify({'error': 'Unexpected server error', 'details': str(e)}), 500


@app.route('/api/documents', methods=['GET'])
@login_required
def list_documents():
    try:
        user_id = session['user_id']
        
        response = table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )

        documents = response.get('Items', [])

        return jsonify({
            'documents': documents,
            'count': len(documents)
        }), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<document_id>', methods=['GET'])
@login_required
def get_document(document_id):
    try:
        user_id = session['user_id']

        response = table.get_item(
            Key={
                'userId': user_id,
                'documentId': document_id
            }
        )

        if 'Item' not in response:
            return jsonify({'error': 'Document not found'}), 404

        document = response['Item']

        # Generate presigned URL for download
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': document['s3Key']
            },
            ExpiresIn=3600  # URL valid for 1 hour
        )

        document['downloadUrl'] = presigned_url

        return jsonify(document), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<document_id>/download', methods=['GET'])
@login_required
def download_document(document_id):
    try:
        user_id = session['user_id']

        response = table.get_item(
            Key={
                'userId': user_id,
                'documentId': document_id
            }
        )

        if 'Item' not in response:
            return jsonify({'error': 'Document not found'}), 404

        document = response['Item']

        # Generate presigned URL
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': document['s3Key'],
                'ResponseContentDisposition': f'attachment; filename="{document["fileName"]}"'
            },
            ExpiresIn=300  # 5 minutes
        )

        return jsonify({'downloadUrl': presigned_url}), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def delete_document(document_id):
    try:
        user_id = session['user_id']

        # Get document metadata
        response = table.get_item(
            Key={
                'userId': user_id,
                'documentId': document_id
            }
        )

        if 'Item' not in response:
            return jsonify({'error': 'Document not found'}), 404

        document = response['Item']

        # Delete from S3
        s3_client.delete_object(
            Bucket=S3_BUCKET,
            Key=document['s3Key']
        )

        # Delete from DynamoDB
        table.delete_item(
            Key={
                'userId': user_id,
                'documentId': document_id
            }
        )

        return jsonify({'message': 'Document deleted successfully'}), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/search', methods=['GET'])
@login_required
def search_documents():
    try:
        user_id = session['user_id']
        query = request.args.get('q', '').lower()

        # Get all user documents
        response = table.query(
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )

        documents = response.get('Items', [])

        # Filter documents based on search query
        filtered_documents = [
            doc for doc in documents
            if query in doc.get('fileName', '').lower() or
               query in doc.get('description', '').lower() or
               any(query in tag.lower() for tag in doc.get('tags', []))
        ]

        return jsonify({
            'documents': filtered_documents,
            'count': len(filtered_documents)
        }), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Web Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)