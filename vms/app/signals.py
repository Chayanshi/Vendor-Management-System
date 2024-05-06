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
      avg_on_time_delivery = calculate_on_time_delivery_rate(vendor_instance,None,None)
      avg_quality_rating = calculate_quality_rating_average(vendor_instance,None,None)
      fulfillment_rate = calculate_fulfillment_rate(vendor_instance,None,None)
      average_response_time = calculate_avg_response_time(vendor_instance,None,None)

      vendor_instance.on_time_delivery_rate = avg_on_time_delivery
      vendor_instance.quality_rating_avg = avg_quality_rating
      vendor_instance.fulfillment_rate = fulfillment_rate
      vendor_instance.average_response_time=average_response_time
      vendor_instance.save()

      update_or_create_historical_record(vendor_instance, instance.delivery_date.month, instance.delivery_date.year)

   elif instance.acknowledgment_date:
      vendor_instance = instance.vendor
      average_response_time = calculate_avg_response_time(vendor_instance)
      vendor_instance.average_response_time=average_response_time
      vendor_instance.save()
      update_or_create_historical_record(vendor_instance, instance.delivery_date.month, instance.delivery_date.year)


def update_or_create_historical_record(vendor_instance, month, year):
   print("\n\nupdate_or_create_historical_record",month,year)

   historical_record, created = HistoricalPerformanceModel.objects.get_or_create(
            vendor=vendor_instance,
            month=month,
            year=year
        )
   
   print("historical_record ",historical_record,"\ncreated ",created)
   avg_on_time_delivery = calculate_on_time_delivery_rate(vendor_instance,month,year)
   avg_quality_rating = calculate_quality_rating_average(vendor_instance,month,year)
   fulfillment_rate = calculate_fulfillment_rate(vendor_instance,month,year)
   average_response_time = calculate_avg_response_time(vendor_instance,month,year)
   
   print("\n\navg_on_time_delivery",avg_on_time_delivery)
   print("avg_quality_rating",avg_quality_rating)
   print("fulfillment_rate",fulfillment_rate)
   print("average_response_time",average_response_time)

   # if created:
   #    print("in created")
   #    created.on_time_delivery_rate = avg_on_time_delivery
   #    created.quality_rating_avg = avg_quality_rating
   #    created.fulfillment_rate = fulfillment_rate
   #    created.average_response_time=average_response_time
   #    created.save()
   # else:
   print("in historical_record")
   historical_record.on_time_delivery_rate = avg_on_time_delivery
   historical_record.quality_rating_avg = avg_quality_rating
   historical_record.fulfillment_rate = fulfillment_rate
   historical_record.average_response_time=average_response_time
   historical_record.save()