


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import (
    CustomUser,
    AdminProfile,
    CompanyStaffProfile,
    UserProfile,
    Company,
    JobCategory,
    Job,
)
from .serializers import (
    CustomUserSerializer,
    AdminProfileSerializer,
    CompanyStaffProfileSerializer,
    UserProfileSerializer,
    CompanySerializer,
    JobCategorySerializer,
    JobSerializer,
)

# Helper function to get the appropriate profile and serializer based on user role
def get_profile(user):
    """
    Retrieve the user's profile and determine the appropriate serializer class.
    """
    print(f"=== Debugging get_profile ===")
    print(f"User: {user.username} (ID: {user.id}, Role: {user.role})")
    
    # Check if the profile exists
    try:
        profile = UserProfile.objects.get(user=user)
        print(f"Profile found: {profile}")
    except UserProfile.DoesNotExist:
        profile = None
        print("Profile not found")
    
    # Determine the serializer class based on the user's role
    if user.role == "user":
        serializer_class = UserProfileSerializer
        print(f"Serializer class: UserSerializer")
    elif user.role == "admin":
        serializer_class = AdminProfileSerializer
        print(f"Serializer class: AdminSerializer")
    else:
        serializer_class = None  # Fallback case
        print("No serializer class matched")
    
    print(f"Returning profile: {profile}, serializer_class: {serializer_class}")
    return profile, serializer_class

from rest_framework.permissions import IsAuthenticatedOrReadOnly
# Authentication Views
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser, AdminProfile, CompanyStaffProfile, UserProfile
from .serializers import CustomUserSerializer

# Add this function near other helper functions at the top
# def generate_and_send_otp(user):
#     """
#     Generate OTP, save it, and send it to the user's email.
#     Returns the generated OTP code.
#     """
#     otp_code = str(random.randint(100000, 999999))
#     EmailOTP.objects.create(user=user, otp_code=otp_code)
#     send_email_otp(user.email, otp_code, is_registration=otp_code)
#     return otp_code

# In the register function, modify the code:
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    email = request.data.get('email')
    print(f"\n=== Registration Request ===")
    print(f"Email received: {email}")
    print(f"Full request data: {request.data}")
    
    # Check for existing email before registration
    if CustomUser.objects.filter(email=email).exists():
        print(f"Email {email} already exists in database")
        return Response({
            'error': 'Email already registered',
            'message': 'Please use a different email address or try logging in'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    print("Email is unique, proceeding with registration")
    
    # Generate username from email if not provided
    user_data = request.data.copy()  # Create a mutable copy of the data
    if not user_data.get('username'):
        username = email.split('@')[0]
        base_username = username
        counter = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        user_data['username'] = username
    
    serializer = CustomUserSerializer(data=user_data)
    if serializer.is_valid():
        # Save user but set is_active to False initially
        user = serializer.save(is_active=False)

        # Create a profile based on the user's role
        if user.role == CustomUser.ADMIN:
            AdminProfile.objects.create(user=user)
        elif user.role == CustomUser.COMPANY_STAFF:
            CompanyStaffProfile.objects.create(user=user)
        else:
            UserProfile.objects.create(user=user)

        # Generate and send OTP
        otp_code = generate_and_send_otp(user)
        send_email_otp(email, otp_code, is_registration=True)

        return Response({
            'message': 'User registered successfully. Please check your email for verification code.',
            'user': serializer.data,
            'require_verification': True,
            'email': user.email
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# # In the login function, replace the OTP generation part:
# @api_view(['POST'])
# @permission_classes([AllowAny])
# def login(request):
#     email = request.data.get('email')
#     password = request.data.get('password')
    
#     try:
#         # Get user by email
#         user = CustomUser.objects.filter(email=email).first()
#         if not user:
#             return Response({'error': 'No user found with this email'}, status=status.HTTP_404_NOT_FOUND)
            
#         # Authenticate user
#         user = authenticate(username=user.username, password=password)
        
#         if not user:
#             return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
#         # Check if email is verified
#         if not user.is_active:
#             # Delete any existing OTP for this user
#             EmailOTP.objects.filter(user=user).delete()
            
#             # Generate and send new OTP
#             otp_code = generate_and_send_otp(user)
            
#             return Response({
#                 'error': 'Email not verified',
#                 'message': 'Please verify your email. A new OTP has been sent.',
#                 'require_verification': True,
#                 'email': user.email,
#                 'otp': otp_code  # Include OTP in response for testing
#             }, status=status.HTTP_403_FORBIDDEN)
        
#         # If email is verified, proceed with login
#         refresh = RefreshToken.for_user(user)
#         return Response({
#             'user': CustomUserSerializer(user).data,
#             'refresh': str(refresh),
#             'access': str(refresh.access_token),
#         })
        
#     except CustomUser.DoesNotExist:
#         return Response({'error': 'No user found with this email'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    try:
        # Get user by email only
        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response({
                'error': 'No user found with this email',
                'message': 'Please check your email or register'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if otp:
            # Verify OTP
            otp_record = EmailOTP.objects.filter(user=user, otp_code=otp).first()
            if not otp_record:
                return Response({
                    'error': 'Invalid OTP',
                    'message': 'Please enter the correct OTP'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Delete used OTP
            otp_record.delete()
            
            # If user is not active, activate their account
            if not user.is_active:
                user.is_active = True
                user.save()
            
            # Generate tokens and login
            refresh = RefreshToken.for_user(user)
            return Response({
                'message': 'Login successful' if user.is_active else 'Email verified and login successful',
                'user': CustomUserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        else:
            # Generate and send new OTP
            EmailOTP.objects.filter(user=user).delete()  # Clear existing OTPs
            otp_code = generate_and_send_otp(user, is_registration=not user.is_active)
            
            return Response({
                'message': 'OTP has been sent to your email',
                'require_verification': not user.is_active,
                'email': user.email,
                'otp': otp_code  # Remove in production
            }, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({
            'error': 'Login failed',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Refresh an access token using a refresh token.
    """
    refresh_token = request.data.get('refresh')
    if not refresh_token:
        return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        refresh = RefreshToken(refresh_token)
        return Response({'access': str(refresh.access_token)})
    except Exception:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)






@api_view(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
def profile(request):
    user = request.user
    profile, serializer_class = get_profile(user)
    
    
    # Debugging: Print basic info
    print(f"\n=== Profile View ===")
    print(f"User: {user.username} (ID: {user.id}, Role: {user.role})")
    print(f"Request Method: {request.method}")
    print(f"Existing Profile: {'Yes' if profile else 'No'}")
    
    if request.method == 'GET':
        if not profile:
            print("GET: Profile not found")
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = serializer_class(profile)
        print("GET: Profile data:", serializer.data)
        return Response(serializer.data)

    elif request.method == 'POST':
        if profile:
            print("POST: Profile already exists")
            return Response({'error': 'Profile already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        print("POST: Request data:", request.data)
        serializer = serializer_class(data=request.data)
        
        if serializer.is_valid():
            print("POST: Valid data. Saving profile...")
            serializer.save(user=user)
            print("POST: Profile created successfully")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print("POST: Validation errors:", serializer.errors)
            return Response({
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
    elif request.method in ['PUT', 'PATCH']:
        if not profile:
            print(f"{request.method}: Profile not found")
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        update_data = request.data.copy()
        
        # Remove user field if present as it's not needed for update
        if 'user' in update_data:
            update_data.pop('user')
            
        print(f"{request.method}: Request data:", update_data)
        serializer = serializer_class(
            profile,
            data=update_data,
            partial=True  # Always use partial update to avoid required field errors
        )
        
        if serializer.is_valid():
            print(f"{request.method}: Valid data. Updating profile...")
            serializer.save()
            
            # Include the existing phone number in response
            response_data = serializer.data
            response_data['phone_number'] = user.phone_number
            print(f"{request.method}: Profile updated successfully")
            return Response(response_data)
        else:
            print(f"{request.method}: Validation errors:", serializer.errors)
            return Response({
                'error': 'Invalid update data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


    elif request.method == 'DELETE':
        if not profile:
            print("DELETE: Profile not found")
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        print("DELETE: Deleting profile...")
        profile.delete()
        print("DELETE: Profile deleted successfully")
        return Response(status=status.HTTP_204_NO_CONTENT)
# Company Views
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def company_list(request):
    """
    List all companies or create a new company.
    """
    if request.method == 'GET':
        companies = Company.objects.all()
        serializer = CompanySerializer(companies, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = CompanySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
def company_detail(request, pk):
    """
    Retrieve, update, or delete a company.
    """
    try:
        company = Company.objects.get(pk=pk)
    except Company.DoesNotExist:
        return Response({'error': 'Company not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = CompanySerializer(company)
        return Response(serializer.data)

    elif request.method in ['PUT', 'PATCH']:
        if company.created_by != request.user and not request.user.is_superuser:
            return Response({'error': 'Not authorized to edit this company'}, status=status.HTTP_403_FORBIDDEN)
        serializer = CompanySerializer(
            company,
            data=request.data,
            partial=request.method == 'PATCH'
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        if company.created_by != request.user and not request.user.is_superuser:
            return Response({'error': 'Not authorized to delete this company'}, status=status.HTTP_403_FORBIDDEN)
        company.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Job Category Views
@api_view(['GET'])
@permission_classes([AllowAny])
def job_category_list(request):
    """
    List all job categories.
    """
    categories = JobCategory.objects.all()
    serializer = JobCategorySerializer(categories, many=True)
    return Response(serializer.data)


# Job Views
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def job_list(request):
    """
    List all jobs or create a new job.
    """
    if request.method == 'GET':
        jobs = Job.objects.all().order_by('-posted_on')
        serializer = JobSerializer(jobs, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(posted_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticatedOrReadOnly])
def job_detail(request, pk):
    """
    Retrieve, update, or delete a job.
    """
    try:
        job = Job.objects.get(pk=pk)
    except Job.DoesNotExist:
        return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = JobSerializer(job)
        return Response(serializer.data)

    elif request.method in ['PUT', 'PATCH']:
        if job.posted_by != request.user and not request.user.is_superuser:
            return Response({'error': 'Not authorized to edit this job'}, status=status.HTTP_403_FORBIDDEN)
        serializer = JobSerializer(
            job,
            data=request.data,
            partial=request.method == 'PATCH'
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        if job.posted_by != request.user and not request.user.is_superuser:
            return Response({'error': 'Not authorized to delete this job'}, status=status.HTTP_403_FORBIDDEN)
        job.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
    
from django.contrib.auth import logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only logged-in users can log out

    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully"}, status=200)


from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import EmailOTP
import random

User = get_user_model()  # Get the correct user model

def send_email_otp(email, otp_code, is_registration=False):
    if is_registration:
        subject = "Welcome - Email Verification"
        message = f"""
Welcome to our platform!

Your email verification code is: {otp_code}
This code is valid for 5 minutes.

Please verify your email to activate your account.
        """
    else:
        subject = "Your OTP Code"
        message = f"Your OTP code is {otp_code}. It is valid for 5 minutes."
    
    print(f"Sending {subject} to: {email}")
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

def generate_and_send_otp(user, is_registration=False):
    """
    Generate OTP, save it, and send it to the user's email.
    Returns the generated OTP code.
    """
    otp_code = str(random.randint(100000, 999999))
    EmailOTP.objects.create(user=user, otp_code=otp_code)
    send_email_otp(user.email, otp_code, is_registration)
    return otp_code

@api_view(["POST"])
@permission_classes([AllowAny])
def resend_otp(request):
    """
    Resend OTP to user's email
    """
    email = request.data.get("email")
    print(f"\n=== Resend OTP Request ===")
    print(f"Email received: {email}")
    
    try:
        user = CustomUser.objects.filter(email=email).first()
        if not user:
            print(f"No user found with email: {email}")
            return Response({"error": "User not found"}, status=404)
            
        # Delete any existing OTP
        EmailOTP.objects.filter(user=user).delete()
        
        # Generate and send new OTP
        otp_code = generate_and_send_otp(user, is_registration=not user.is_active)
        
        print(f"New OTP generated and sent to: {email}")
        return Response({
            "message": "OTP resent successfully",
            "email": email,
            "otp": otp_code  # Remove in production
        }, status=200)
        
    except Exception as e:
        print(f"Error during OTP resend: {str(e)}")
        return Response({"error": "Failed to resend OTP"}, status=400)


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email_otp(request):
    email = request.data.get("email")
    otp_code = request.data.get("otp")
    print(f"\n=== OTP Verification Request ===")
    print(f"Email: {email}, OTP: {otp_code}")

    try:
        # Check if user exists
        user = CustomUser.objects.filter(email=email).first()
        if not user:
            print(f"No user found with email: {email}")
            return Response({
                "status": "error",
                "message": "Account not found",
                "details": "Please register first or check your email address"
            }, status=404)

        # Get all OTPs for debugging
        all_otps = EmailOTP.objects.filter(user=user)
        print(f"All OTPs for user {email}: {[otp.otp_code for otp in all_otps]}")

        # Get the most recent OTP
        otp_record = all_otps.order_by('-created_at').first()
        
        if not otp_record:
            print(f"No OTP records found for user: {email}")
            return Response({
                "status": "error",
                "message": "No verification code found",
                "details": "Please request a new verification code"
            }, status=400)

        print(f"Comparing OTPs - Received: {otp_code}, Stored: {otp_record.otp_code}")
        if otp_record.otp_code != otp_code:
            print(f"OTP mismatch for user: {email}")
            return Response({
                "status": "error",
                "message": "Invalid verification code",
                "details": "The code you entered is incorrect"
            }, status=400)

        # Success path
        user.is_active = True
        user.save()
        otp_record.delete()
        
        refresh = RefreshToken.for_user(user)
        print(f"Successfully verified email for user: {email}")
        
        return Response({
            "status": "success",
            "message": "Email verified successfully",
            "user": CustomUserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }, status=200)

    except Exception as e:
        print(f"Verification error for {email}: {str(e)}")
        return Response({
            "status": "error",
            "message": "Verification failed",
            "details": str(e)
        }, status=500)
