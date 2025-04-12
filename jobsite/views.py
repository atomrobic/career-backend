


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

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """
    Register a new user and create a corresponding profile.
    Tokens are not generated during registration.
    """
    serializer = CustomUserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Create a profile based on the user's role
        if user.role == CustomUser.ADMIN:
            AdminProfile.objects.create(user=user)
        elif user.role == CustomUser.COMPANY_STAFF:
            CompanyStaffProfile.objects.create(user=user)
        else:
            UserProfile.objects.create(user=user)

        return Response({
            'message': 'User registered successfully.',
            'user': serializer.data,
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """
    Authenticate a user using email and return JWT tokens.
    """
    email = request.data.get('email')
    password = request.data.get('password')
    
    try:
        # Get user by email
        user = CustomUser.objects.get(email=email)
        # Authenticate user
        user = authenticate(username=user.username, password=password)
        
        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if email is verified
        if not user.is_active:
            # Generate and send new OTP
            otp_code = str(random.randint(100000, 999999))
            EmailOTP.objects.create(user=user, otp_code=otp_code)
            send_email_otp(user.email, otp_code)
            
            return Response({
                'error': 'Email not verified',
                'message': 'Please verify your email. A new OTP has been sent.',
                'require_verification': True,
                'email': user.email
            }, status=status.HTTP_403_FORBIDDEN)
        
        # If email is verified, proceed with login
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': CustomUserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
        
    except CustomUser.DoesNotExist:
        return Response({'error': 'No user found with this email'}, status=status.HTTP_404_NOT_FOUND)

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

def send_email_otp(email, otp_code):
    subject = "Your OTP Code"
    message = f"Your OTP code is {otp_code}. It is valid for 5 minutes."
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

@api_view(["POST"])
def send_email_verification(request):
    email = request.data.get("email")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

    otp_code = str(random.randint(100000, 999999))
    EmailOTP.objects.create(user=user, otp_code=otp_code)

    send_email_otp(email, otp_code)  # Send OTP via email
    return Response({"message": "OTP sent successfully"}, status=200)

@api_view(["POST"])
def verify_email_otp(request):
    email = request.data.get("email")
    otp_code = request.data.get("otp")

    try:
        user = User.objects.get(email=email)
        otp_record = EmailOTP.objects.filter(user=user, otp_code=otp_code).last()

        if otp_record and otp_record.is_valid():
            otp_record.delete()  # Remove OTP after verification
            return Response({"message": "Email verified successfully"}, status=200)
        else:
            return Response({"error": "Invalid or expired OTP"}, status=400)

    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)