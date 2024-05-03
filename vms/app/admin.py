from django.contrib import admin
from .models import User_model,Vendor_model,HistoricalPerformanceModel,Items_model,Purchase_order_model

# Register your models here.
admin.site.register([User_model,Vendor_model,HistoricalPerformanceModel,Items_model,Purchase_order_model])