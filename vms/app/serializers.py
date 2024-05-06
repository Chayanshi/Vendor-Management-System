from rest_framework import serializers
from .models import *
import random
import string

def generate_vendor_code():
    length = 10
    characters = string.ascii_letters + string.digits
    random_code = ''.join(random.choice(characters) for _ in range(length))
    print("serializer random_code",type(random_code),random_code)
    return random_code

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorModel
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_model
        fields = ['email', 'username', 'password', 'phone', 'address', 'user_role']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        try:
            print("validated_data",validated_data)
            role = validated_data.get('user_role', None)
            if role == 'Vendor':
                vendor_data = {
                    'contact_details': validated_data.get('contact_details', None),
                    'code': generate_vendor_code()
                }
                print("validated_data",validated_data)
                user_instance = User_model.objects.create(**validated_data)
                vendor_data['user'] = user_instance
                print("vendor_data",vendor_data)
                vendor_instance = VendorModel.objects.create(**vendor_data)
                print("user created with user and vendor model")
                return user_instance
            else:
                user_instance = User_model.objects.create(**validated_data)
                print("user created with user")
                return user_instance
        except Exception as e:
            print("error in serializer \n",str(e))
            return None
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.user_role.lower() == 'vendor':
            try:
                vendor_instance = instance.vendor_user
                vendor_serializer = VendorSerializer(vendor_instance)
                data['vendor_details'] = vendor_serializer.data
            except VendorModel.DoesNotExist:
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
            except VendorModel.DoesNotExist:
                print("DoesNotExist")
                pass 
        
        return instance

class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ItemsModel
        fields = "__all__"

        
class PurchaseOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchaseOrderModel
        fields = "__all__"

    def to_representation(self, instance):
        data = super().to_representation(instance)
        print(instance,"\n",data)
        try:
            items = []
            for item_id in data['items']:
                item_instance = ItemsModel.objects.get(id=item_id)
                print("item_instance",item_instance)
                item_serializer = ItemSerializer(item_instance)
                print("item_serializer",item_serializer.data)
                items.append(item_serializer.data)

            data['items'] = items
        except VendorModel.DoesNotExist:
            data['vendor_details'] = None
            
        return data
    
