from .models import *
import random
import string
from django.utils import timezone


def calculate_quality_rating_average(vendor):
    print("in helper calculate_quality_rating_average")
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
    print("in helper calculate_on_time_delivery_rate")
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
    print("in helper calculate_fulfillment_rate")
    total_orders = PurchaseOrderModel.objects.filter(vendor=vendor).count()
    fulfilled_orders = PurchaseOrderModel.objects.filter(vendor=vendor, status='completed').count()

    if total_orders > 0:
        fulfillment_rate = fulfilled_orders / total_orders
    else:
        fulfillment_rate = 0

    return fulfillment_rate


def calculate_avg_response_time(vendor):
    print("in helper calculate_avg_response_time",vendor)
    total_response_time = 0
    acknowledged_orders = PurchaseOrderModel.objects.filter(
        vendor=vendor, acknowledgment_date__isnull=False
    )

    for order in acknowledged_orders:
        response_time = order.acknowledgment_date - order.issue_date
        print("response_time",response_time)
        total_response_time += response_time.total_seconds()
    
    print("total_response_time",total_response_time)
    average_response_time = total_response_time / acknowledged_orders.count()
    print("average_response_time",average_response_time)
    average_response_timedelta = timezone.timedelta(seconds=average_response_time)

    # Format the timedelta as HH:MM:SS
    average_response_formatted = str(average_response_timedelta)
    print("Average Response Time:", average_response_formatted.split('.')[0])
    return average_response_formatted.split('.')[0]
