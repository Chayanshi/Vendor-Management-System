from django.contrib import admin
from .models import User_model,VendorModel,HistoricalPerformanceModel,ItemsModel,PurchaseOrderModel

# Register your models here.
admin.site.register([User_model,VendorModel,HistoricalPerformanceModel,ItemsModel,PurchaseOrderModel])