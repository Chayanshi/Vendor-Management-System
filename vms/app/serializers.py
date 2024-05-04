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

def calculate_quality_rating_average(vendor):
    completed_pos = PurchaseOrderModel.objects.filter(vendor=vendor, status='completed')
    total_quality_rating = 0
    total_completed_pos_with_rating = 0

    for po in completed_pos:
        if po.quality_rating is not None:
            total_quality_rating += po.quality_rating
            total_completed_pos_with_rating += 1

    print("total_quality_rating",total_quality_rating)
    print("total_completed_pos_with_rating",total_completed_pos_with_rating)
    if total_completed_pos_with_rating > 0:
        quality_rating_average = total_quality_rating / total_completed_pos_with_rating
    else:
        quality_rating_average = 0
        
    return quality_rating_average

def calculate_on_time_delivery_rate(vendor):
    completed_pos = PurchaseOrderModel.objects.filter(vendor=vendor, status='completed')
    total_completed_pos = completed_pos.count()
    on_time_deliveries = 0

    for po in completed_pos:
        if po.actual_delivered_date <= po.delivery_date:
            on_time_deliveries += 1
    
    print("on_time_deliveries",on_time_deliveries)
    print("total_completed_pos",total_completed_pos)
    if total_completed_pos > 0:
        on_time_delivery_rate = (on_time_deliveries / total_completed_pos) * 100
    else:
        on_time_delivery_rate = 0 

    return on_time_delivery_rate

def calculate_fulfillment_rate(vendor):
    total_orders = PurchaseOrderModel.objects.filter(vendor=vendor).count()
    fulfilled_orders = PurchaseOrderModel.objects.filter(vendor=vendor, status='completed').count()

    if total_orders > 0:
        fulfillment_rate = fulfilled_orders / total_orders
    else:
        fulfillment_rate = 0

    return fulfillment_rate

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
            vendor_instance = VendorModel.objects.create(**vendor_data)
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
    
    def update(self, instance, validated_data):
        print(validated_data)
        print("validated_data.status",validated_data.get("status"))
        print("instance status",instance)

        # items_data = validated_data.pop('items', None)
        # print("////",items_data)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()

        # if items_data is not None:
        #     instance.items.clear()
        #     print("\ninstance.items",instance.items)
        #     for item_id in items_data:
        #         print("item_id",item_id.id)
        #         item_instance = ItemsModel.objects.get(id=item_id.id)
        #         print("item_instance",item_instance)
        #         instance.items.set(item_instance)
        print("instance",instance)


        vendor_instance = VendorModel.objects.get(id=int(instance.vendor.id))
        print("vendor_instance",vendor_instance)
        if validated_data.get("status").lower() == "completed":
            print("instance.vendor.id",instance.vendor.id)
            avg_on_time_delivery = calculate_on_time_delivery_rate(vendor_instance)
            avg_quality_rating = calculate_quality_rating_average(vendor_instance)
            fulfillment_rate = calculate_fulfillment_rate(vendor_instance)

            print("avg_on_time_delivery",avg_on_time_delivery)
            print("avg_quality_rating",avg_quality_rating)
            print("fulfillment_rate",fulfillment_rate)
            vendor_instance.on_time_delivery_rate = avg_on_time_delivery
            vendor_instance.quality_rating_avg = avg_quality_rating
            vendor_instance.fulfillment_rate = fulfillment_rate
            vendor_instance.save()

            return super().update(instance, validated_data)
        elif "status" in validated_data:
            fulfillment_rate = calculate_fulfillment_rate(vendor_instance)
            vendor_instance.fulfillment_rate = fulfillment_rate
            vendor_instance.save()

        return instance
