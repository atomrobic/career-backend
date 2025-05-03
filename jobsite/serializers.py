
from rest_framework import serializers
from .models import (
    CustomUser,
    AdminProfile,
    CompanyStaffProfile,
    UserProfile,
    Company,
    JobCategory,
    Job,
)

# ... existing imports ...

# Serializer for UserProfile
class CustomUserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = [
            'id',
            'username',
            'email',
            'password1',
            'password2',
            'phone_number',
            'role',
        ]
        extra_kwargs = {
            'password1': {'write_only': True},
            'password2': {'write_only': True},
        }

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        password = validated_data.pop('password1')
        validated_data.pop('password2')
        user = CustomUser(**validated_data)
        user.set_password(password)
        user.save()
        return user
# Serializer for AdminProfile
class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminProfile
        fields = '__all__'


# Serializer for CompanyStaffProfile
class CompanyStaffProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyStaffProfile
        fields = '__all__'


# Serializer for UserProfile
class UserProfileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    phone_number = serializers.CharField(source='user.phone_number')
    email = serializers.CharField(source='user.email', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'phone_number', 'email', 'username', 'education', 'skills', 'experience', 'personal_info']

    def update(self, instance, validated_data):
        # Handle phone number update
        if 'user' in validated_data and 'phone_number' in validated_data['user']:
            instance.user.phone_number = validated_data['user']['phone_number']
            instance.user.save()

        # Update other fields
        instance.education = validated_data.get('education', instance.education)
        instance.skills = validated_data.get('skills', instance.skills)
        instance.experience = validated_data.get('experience', instance.experience)
        instance.personal_info = validated_data.get('personal_info', instance.personal_info)
        instance.save()
        return instance
# Serializer for Company
class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'
        read_only_fields = ['created_by']  # Ensure created_by is not editable

    def create(self, validated_data):
        # Automatically set the `created_by` field to the current user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


# Serializer for JobCategory
class JobCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = JobCategory
        fields = '__all__'


# Serializer for Job
class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'
        read_only_fields = ['posted_by']  # Ensure posted_by is not editable

    def create(self, validated_data):
        # Automatically set the `posted_by` field to the current user
        validated_data['posted_by'] = self.context['request'].user
        return super().create(validated_data)
    
    