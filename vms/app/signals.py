from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import *
from .helpers import calculate_on_time_delivery_rate, calculate_avg_response_time, calculate_quality_rating_average, calculate_fulfillment_rate

@receiver(post_save, sender=PurchaseOrderModel)
def update_performance_metrics(sender, instance, created, **kwargs):
   print("in signals",instance)
   if instance.status == 'completed':
      vendor_instance = instance.vendor
      print("in signals",vendor_instance)
      avg_on_time_delivery = calculate_on_time_delivery_rate(vendor_instance)
      avg_quality_rating = calculate_quality_rating_average(vendor_instance)
      fulfillment_rate = calculate_fulfillment_rate(vendor_instance)
      average_response_time = calculate_avg_response_time(vendor_instance)

      vendor_instance.on_time_delivery_rate = avg_on_time_delivery
      vendor_instance.quality_rating_avg = avg_quality_rating
      vendor_instance.fulfillment_rate = fulfillment_rate
      vendor_instance.average_response_time=average_response_time
      vendor_instance.save()
   elif instance.acknowledgment_date:
      vendor_instance = instance.vendor
      average_response_time = calculate_avg_response_time(vendor_instance)
      vendor_instance.average_response_time=average_response_time
      vendor_instance.save()
