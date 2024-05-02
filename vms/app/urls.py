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
   path("UserLogin",UserLogin.as_view()),
   path("UserLogout",UserLogout.as_view()),
   path("SendOTP",SendOTP.as_view()),
   path("VerifyOTP",VerifyOTP.as_view()),
   path("ForgotPassword",ForgotPassword.as_view()),
   path("ChangePassword",ChangePassword.as_view()),

   path("CreateVendor",CreateVendor.as_view()),
   path("CreateUser",CreateUser.as_view()),
   
   path("UpdateUser",UpdateUser.as_view()),
   path("DeleteUser",DeleteUser.as_view()),
   path("GetallUser",GetallUser.as_view()),
   path("Get_ParticularUser",Get_ParticularUser.as_view()),

   path("CreateItem",CreateItem.as_view()),
   path("UpdateItem",UpdateItem.as_view()),
   path("DeleteItem",DeleteItem.as_view()),
   path("GetallItem",GetallItem.as_view()),
   path("Get_ParticularItem",Get_ParticularItem.as_view()),
]