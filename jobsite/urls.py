# """
# URL configuration for myproject project.

# The `urlpatterns` list routes URLs to views. For more information please see:
#     https://docs.djangoproject.com/en/4.2/topics/http/urls/
# Examples:
# Function views
#     1. Add an import:  from my_app import views
#     2. Add a URL to urlpatterns:  path('', views.home, name='home')
# Class-based views
#     1. Add an import:  from other_app.views import Home
#     2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
# Including another URLconf
#     1. Import the include() function: from django.urls import include, path
#     2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
# """
# from django.contrib import admin

# from django.urls import path
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


# from jobsite.views import (
#     register,
#     login,
#     refresh_token,
#     profile,
#     company_list,
#     company_detail,
#     job_category_list,
#     job_list,
#     job_detail,LogoutView,send_email_verification, verify_email_otp
# )

# urlpatterns = [
#     # JWT Authentication Endpoints
#         path('admin/', admin.site.urls),  # Change 'custom-admin' to your preferred URL

#     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

#     # User Authentication and Registration
#     path('api/register/', register, name='register'),
#     path('', login, name='login'),
#     path('api/refresh-token/', refresh_token, name='refresh_token'),

#     # Profile Management
#     path('api/profile/', profile, name='profile'),

#     # Company Endpoints
#     path('api/companies/', company_list, name='company_list'),
#     path('api/companies/<int:pk>/', company_detail, name='company_detail'),

#     # Job Category Endpoints
#     path('api/job-categories/', job_category_list, name='job_category_list'),

#     # Job Endpoints
#     path('api/jobs/', job_list, name='job_list'),
#     path('api/jobs/<int:pk>/', job_detail, name='job_detail'),
#     path('logout/', LogoutView.as_view(), name='logout'),
#     path("auth/send-email-otp/", send_email_verification, name="send_email_otp"),
#     path("auth/verify-email-otp/", verify_email_otp, name="verify_email_otp"),
#     # Basic job CRUD
    
#     # OCR endpoint
# ]

from django.urls import path
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from jobsite.views import (
    register,
    login,
    refresh_token,
    profile,
    company_list,
    company_detail,
    job_category_list,
    job_list,
    job_detail,
    LogoutView,
send_email_otp,    verify_email_otp,
    resend_otp
)

# 👇 Home view for base URL
def home_view(request):
    return JsonResponse({
        "message": "Welcome to the Job Portal API. Please use the documented endpoints."
    })

urlpatterns = [

    # Root route - safe for GET

    # JWT Authentication
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Custom login and register
    path('api/register/', register, name='register'),
    path('api/login/', login, name='login'),
    path('api/refresh-token/', refresh_token, name='refresh_token'),
    path('api/profile/', profile, name='profile'),
    path('', home_view, name='home'),  # Add this line for root URL

    # Company
    path('api/companies/', company_list, name='company_list'),
    path('api/companies/<int:pk>/', company_detail, name='company_detail'),

    # Job Categories and Jobs
    path('api/job-categories/', job_category_list, name='job_category_list'),
    path('api/jobs/', job_list, name='job_list'),
    path('api/jobs/<int:pk>/', job_detail, name='job_detail'),
    path('api/resend-otp/', resend_otp, name='resend-otp'),  # Changed from views.resend_otp
    path('api/send-otp/', send_email_otp, name='send_email_otp'),
    path('verify-otp/', verify_email_otp, name='verify_otp'),
]