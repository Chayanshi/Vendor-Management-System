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


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_model
        fields = ['email', 'username', 'password', 'phone', 'address', 'user_role']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        print("validated_data",validated_data)
        role = validated_data.get('user_role', None)
        if role.lower() == 'vendor':
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
            return user_instance
        else:
            user_instance = User_model.objects.create_user(**validated_data)
            print("user created with user")
            return user_instance
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.user_role.lower() == 'vendor':
            try:
                vendor_instance = instance.vendor_user
                vendor_serializer = VendorSerializer(vendor_instance)
                data['vendor_details'] = vendor_serializer.data
            except Vendor_model.DoesNotExist:
                data['vendor_details'] = None
        return data

    def update(self, instance, validated_data):
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if instance.user_role.lower() == 'vendor':
            try:
                print(instance.vendor_user)
                vendor_instance = instance.vendor_user
                vendor_serializer = VendorSerializer(vendor_instance, data=validated_data.get('vendor_details', {}), partial=True)
                if vendor_serializer.is_valid():
                    vendor_serializer.save()
            except Vendor_model.DoesNotExist:
                print("DoesNotExist")
                pass 
        
        return instance

class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Items_model
        fields = "__all__"
class PurchaseOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Purchase_order_model
        fields = "__all__"