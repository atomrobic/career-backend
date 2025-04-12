from django.contrib import admin
from .models import CustomUser, Company, JobCategory, Job,UserProfile

# Register Custom User Model
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'email', 'phone_number', 'role')
    search_fields = ('username', 'email', 'phone_number')
    list_filter = ('role',)
    ordering = ('id',)

# Register Company Model
@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'location', 'created_by','email')
    search_fields = ('name', 'location')
    list_filter = ('location',)
    ordering = ('id',)

# Register Job Category Model
@admin.register(JobCategory)
class JobCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)
    ordering = ('id',)

# Register Job Model
@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'company', 'category', 'location', 'salary', 'posted_on')
    search_fields = ('title', 'company__name', 'category__name', 'location')
    list_filter = ('company', 'category', 'location')
    ordering = ('-posted_on',)

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'education', 'experience')  # Columns to display in the list view
    search_fields = ('user__username', 'education', 'skills')  # Searchable fields
    list_filter = ('education',)  # Filter options
    readonly_fields = ('user',)  # Make the user field read-only in the admin panel

admin.site.register(UserProfile, UserProfileAdmin)