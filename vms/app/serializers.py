from rest_framework import serializers
from .models import *
import random
import string

def generate_vendor_code():
    length = 10
    characters = string.ascii_letters + string.digits
    random_code = ''.join(random.choice(characters) for _ in range(length))
    print("serializer random_code",random_code)
    return random_code

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor_model
        fields = "__all__"

class UserSerializer(serializers.Serializer):
    class Meta:
        model = User_model
        fields = ['email', 'username', 'password', 'phone', 'address', 'user_role']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        role = validated_data.get('role', None)
        if role == 'vendor':
            vendor_data = {
                'contact_details': validated_data.get('contact_details', None),
                'code': generate_vendor_code(),
                'on_time_delivery_rate': validated_data.get('on_time_delivery_rate', 0),
                'quality_rating_avg': validated_data.get('quality_rating_avg', 0),
                'average_response_time': validated_data.get('average_response_time', 0),
                'fulfillment_rate': validated_data.get('fulfillment_rate', 0)
            }
            user_instance = User_model.objects.create_user(**validated_data)
            vendor_data['user'] = user_instance
            vendor_instance = Vendor_model.objects.create(**vendor_data)
            print("user created with user and vendor model")
        else:
            user_instance = User_model.objects.create_user(**validated_data)
            print("user created with user")
            return user_instance
    
    def to_representation(self, instance):
        if instance.role == 'vendor':
            try:
                vendor_instance = Vendor_model.objects.get(user=instance)
                serializer = VendorSerializer(vendor_instance)
                return serializer.data
            except Vendor_model.DoesNotExist:
                return {'error': 'Vendor details not found'}
        else:
            return super().to_representation(instance)
