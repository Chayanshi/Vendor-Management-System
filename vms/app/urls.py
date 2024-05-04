from django.urls import path, include
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import *

schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Vendor Management System API's",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path("api/UserLogin",UserLogin.as_view()),
   path("api/UserLogout",UserLogout.as_view()),
   path("api/SendOTP",SendOTP.as_view()),
   path("api/VerifyOTP",VerifyOTP.as_view()),
   path("api/ForgotPassword",ForgotPassword.as_view()),
   path("api/ChangePassword",ChangePassword.as_view()),

   path("api/CreateVendor",CreateVendor.as_view()),
   path("api/CreateUser",CreateUser.as_view()),
   
   path("api/UpdateUser",UpdateUser.as_view()),
   path("api/DeleteUser",DeleteUser.as_view()),
   path("api/GetallUser",GetallUser.as_view()),
   path("api/Get_ParticularUser",Get_ParticularUser.as_view()),

   path("api/CreateItem",CreateItem.as_view()),
   path("api/UpdateItem",UpdateItem.as_view()),
   path("api/DeleteItem",DeleteItem.as_view()),
   path("api/GetallItem",GetallItem.as_view()),
   path("api/Get_ParticularItem",Get_ParticularItem.as_view()),

   path("api/Create_PurchaseOrder",Create_PurchaseOrder.as_view()),
   path("api/GetallPurchaseOrder",GetallPurchaseOrder.as_view()),
   path("api/Get_ParticularPurchaseOrder",Get_ParticularPurchaseOrder.as_view()),
   path("api/UpdatePurchaseOrder",UpdatePurchaseOrder.as_view()),
   path("api/DeleteItem",DeleteItem.as_view()),

   path("api/PurchaseOrders/AcknowledgePurchaseOrder/<int:id>",AcknowledgePurchaseOrder.as_view()),
]