from django.shortcuts import render
from .models import *
from .serializers import *
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import login,logout,authenticate
from django.contrib.auth.hashers import make_password,check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import re
from datetime import datetime
from django.utils import timezone
from .email import *
from django.db.models import Q
# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
    
def get_random_otp():
    randomotp = random.randint(0000, 9999)
    return randomotp 


#API to create a user with roles and details
class CreateUser(APIView):
   @swagger_auto_schema(
        operation_description="You can create a user as per roles like admin, vendor and user",
        operation_summary="Create User as per required fields",
        tags=['Admin'],
        request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=['email','password'],
                properties={
                    'email':openapi.Schema(type=openapi.TYPE_STRING,default='testing@mailinator.com'),
                    'username':openapi.Schema(type=openapi.TYPE_STRING),
                    'password':openapi.Schema(type=openapi.TYPE_STRING),
                    'phone':openapi.Schema(type=openapi.TYPE_NUMBER),
                    'address':openapi.Schema(type=openapi.TYPE_STRING),
                    'user_role':openapi.Schema(type=openapi.TYPE_STRING),
                    'contact_details':openapi.Schema(type=openapi.TYPE_STRING,description="Any other relevant contact information"),
                }
            ),
    )
   def post(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        try:
            input_data = request.data
            
            if not re.match(email_regex, input_data['email']):
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
            
            if re.match(password_pattern, input_data['password']):
                print("input_data['password']",input_data['password'])
                # password = make_password(input_data['password'])
                
                # input_data['password'] = password
                if input_data['user_role'].lower() =='admin':
                    print("admin created")
                    input_data['is_superuser']=True
                    input_data['is_staff']=True
                
                print("input_data",input_data)
                serializers = UserSerializer(data=input_data)
                if serializers.is_valid():
                    serializers.save()

                    return Response({'status':status.HTTP_201_CREATED,'response':'User creared successfully'},status=status.HTTP_201_CREATED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'User can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password must contain a upper letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,'response':e},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#API to create vendor
class CreateVendor(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
            operation_description="You can create a user as per roles like admin, vendor and user. Only a admin can create vendor",
            operation_summary="Create User as per required details",
            tags=['Vendor'],
            request_body=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    required=['email','password'],
                    properties={
                        'email':openapi.Schema(type=openapi.TYPE_STRING,default='testing@mailinator.com'),
                        'username':openapi.Schema(type=openapi.TYPE_STRING),
                        'password':openapi.Schema(type=openapi.TYPE_STRING),
                        'phone':openapi.Schema(type=openapi.TYPE_NUMBER),
                        'address':openapi.Schema(type=openapi.TYPE_STRING),
                        'contact_details':openapi.Schema(type=openapi.TYPE_STRING,description="Any other relevant contact information"),
                    }
                ),
                manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication")
            ]
        )
    def post(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        try:
            if not request.user:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':"Login to you account to create a vendor"},status=status.HTTP_400_BAD_REQUEST)
            
            if request.user.user_role == "Admin":
                input_data = request.data
                
                if not re.match(email_regex, input_data['email']):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format, eg: xyz@gmail.com"}, status=status.HTTP_400_BAD_REQUEST)
                
                if re.match(password_pattern, input_data['password']):
                    password = make_password(input_data['password'])
                    
                    input_data['password'] = password
                    input_data['user_role'] = "Vendor"
                    
                    
                    print("input_data",input_data)
                    serializers = UserSerializer(data=input_data)
                    if serializers.is_valid():
                        serializers.save(password=password)

                        return Response({'status':status.HTTP_201_CREATED,'response':'Vendor creared successfully'},status=status.HTTP_201_CREATED)
                    return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Vendor can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password must contain a capital letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':"You don't have authentication to create a vendor. Only a admin can create a Vendor"},status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,'response':e},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#UserLogin     
class UserLogin(APIView):
    @swagger_auto_schema(
        operation_description="Fill details to login",
        operation_summary="User Login",
        tags=['Admin','Vendor'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email','password'],
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING,default="testing@mailinator.com"),
                'password':openapi.Schema(type=openapi.TYPE_STRING,default="Tester@123")
            }
        )
    )
    def post(self,request):
        try:
            email=request.data.get('email')
            password=request.data.get('password')

            user = User_model.objects.get(email=email)
            # Debugging: Print hashed password retrieved from the database
            print("Hashed Password from Database:", user.password)

            # Debugging: Print provided password and hashed password comparison result
            print("Provided Password:", password)
            print("Password Comparison Result:", check_password(password, user.password))

            user = authenticate(request, email=email, password=password)
            if user.is_block == False and user is not None :
                if check_password(password,user.password): 
                    token=get_tokens_for_user(user)
                    request.session['access_token'] = token
                    request.session.save()    
                    login(request,user)
                    return Response({'status':status.HTTP_202_ACCEPTED,'response':'Logged In successfull','access_token':token},status=status.HTTP_202_ACCEPTED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password is incorrect'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_401_UNAUTHORIZED,"response":"User account is blocked"},status=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as e:
            return Response({'status':status.HTTP_404_NOT_FOUND,'response':'User not found, check you email',"error":str(e)},status=status.HTTP_404_NOT_FOUND)

class UserLogout(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Retrieve user profile data by ID",
        operation_summary="logout user by id",
        tags=['Admin','Vendor'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
    )
    def get(self,request,id):
            try:
                user = User_model.objects.get(id=id)
                user2=request.user
                logout(request)
                return Response({'status':status.HTTP_200_OK,'Response':'logout successfuly'},status.HTTP_200_OK)
            except User_model.DoesNotExist:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':'user not found'},status.HTTP_400_BAD_REQUEST)

class SendOTP(APIView):
    @swagger_auto_schema(
        operation_description="enter your account detail to get verification email",
        operation_summary="Send email",
        tags=['Forgot Password'],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp")
        ]
    )
    def get(self, request):
        email = request.query_params.get('email')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"User not found"},status=status.HTTP_400_BAD_REQUEST)
            
            otp=get_random_otp()
            print(otp)
            sendotp(otp=otp,email=email)
            user.otp = otp
            user.save()
            # if email_result == 1:
            return Response({'status':status.HTTP_200_OK,'Response':"Check your email for otp"},status=status.HTTP_200_OK)
            # return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"OTP can't be sended on this email"},status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"error":str(e)},status=status.HTTP_400_BAD_REQUEST)

class VerifyOTP(APIView):
    @swagger_auto_schema(
        operation_description="Verify the sended OTP to user email. The otp is verifed till 3 min of when the otp is sended. If otp expires re-send otp.",
        operation_summary="OTP verification",
        tags=['Forgot Password'],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('OTP',openapi.IN_QUERY,type=openapi.TYPE_INTEGER,description="Enter verification otp, sended on your email")
        ]
    )
    
    def get(self, request):
        email = request.query_params.get('email')
        entered_otp = request.query_params.get('OTP')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"email not found"},status=status.HTTP_400_BAD_REQUEST)
            
            print('db',user.otp)
            print('user',entered_otp)
           
            if int(entered_otp) == user.otp and (timezone.now() - user.otp_created_at).seconds <=180:
                user.otp_verified = True
                user.save()
                return Response({'status':status.HTTP_200_OK,'Response':"Otp Verified"},status=status.HTTP_200_OK)
            return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"OTP is not valid, the OTP Valid period is 2 min"},status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"error":str(e)},status=status.HTTP_400_BAD_REQUEST)
               
class ForgotPassword(APIView):
    @swagger_auto_schema(
        operation_description="Have to verify email with otp, then change the password if you have forgot your password",
        operation_summary="Forgot password",
        tags=['Forgot Password'],
        request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=['new_password','confirm_new_password'],
                properties={
                    'new_password':openapi.Schema(type=openapi.TYPE_STRING),
                    'confirm_new_password':openapi.Schema(type=openapi.TYPE_STRING)
                }
            ),
        
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
           
        ]
    )
    def put(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        email = request.query_params.get('email')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"email not found"},status=status.HTTP_400_BAD_REQUEST)
            
            if not user.otp_verified:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"Verify email to change password"},status=status.HTTP_400_BAD_REQUEST)
                
            input = request.data
            print(input['new_password'])
            if str(input['new_password']) == str(input['confirm_new_password']):
                if re.match(password_pattern, input['new_password']):
                    hash_password = make_password(input['new_password'])
                    user.password = hash_password
                    user.save()
                    return Response({'status':status.HTTP_200_OK,'Response':"password changed successfully"},status=status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'password must contain a capital letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'password not match'},status=status.HTTP_400_BAD_REQUEST)
            
        
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"error":str(e)},status=status.HTTP_400_BAD_REQUEST)

class ChangePassword(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Have to verify email with otp, then change the password.",
        operation_summary="Change password",
        tags=['Change Password'],
        request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=['new_password','confirm_new_password'],
                properties={
                    'current_password':openapi.Schema(type=openapi.TYPE_STRING),
                    'new_password':openapi.Schema(type=openapi.TYPE_STRING),
                    'confirm_new_password':openapi.Schema(type=openapi.TYPE_STRING)
                }
            ),
        
        manual_parameters=[
            # openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication")
        ]
    )
    def put(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        # email = request.query_params.get('email')
        email = request.user
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"email not found"},status=status.HTTP_400_BAD_REQUEST)
             
            input = request.data
            print(input['new_password'])
            if check_password(str(input['current_password']),user.password):  
                if str(input['new_password']) == str(input['confirm_new_password']):
                    if re.match(password_pattern, input['new_password']):
                        hash_password = make_password(input['new_password'])
                        user.password = hash_password
                        user.save()
                        return Response({'status':status.HTTP_200_OK,'Response':"password changed successfully"},status=status.HTTP_200_OK)
                    return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'password must contain a capital letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'confirm password and new pasword not match'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'current password not match'},status=status.HTTP_400_BAD_REQUEST)
            
        
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"error":str(e)},status=status.HTTP_400_BAD_REQUEST)
         
#Update User
class UpdateUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update User details",
        operation_summary="User Update",
        tags=['Admin','Vendor'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'username':openapi.Schema(type=openapi.TYPE_STRING),
                'phone':openapi.Schema(type=openapi.TYPE_NUMBER),
                'address':openapi.Schema(type=openapi.TYPE_STRING),
                'contact_details':openapi.Schema(type=openapi.TYPE_STRING,description="Any other relevant contact information"),
            }
        ),
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Enter email to get verification otp"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication")
        ]
    )
    def put(self, request):
        email = request.query_params.get('email')

        try:
            try:
                user = User_model.objects.get(email=email)
            except User_model.DoesNotExist:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "User not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            input_data = request.data
            print(input_data)
            
            # Separate user data and vendor data
            user_data = {k: v for k, v in input_data.items() if k not in ['contact_details', 'on_time_delivery_rate', 'quality_rating_avg', 'average_response_time', 'fulfillment_rate']}
            vendor_data = {k: v for k, v in input_data.items() if k in ['contact_details', 'on_time_delivery_rate', 'quality_rating_avg', 'average_response_time', 'fulfillment_rate']}

            # Update user data
            ser = UserSerializer(user, data=user_data, partial=True)
            if ser.is_valid():
                user_instance = ser.save()

                # Update vendor data if the user is a vendor
                if user_instance.user_role.lower() == 'vendor':
                    try:
                        vendor_instance = user_instance.vendor_user
                        vendor_serializer = VendorSerializer(vendor_instance, data=vendor_data, partial=True)
                        if vendor_serializer.is_valid():
                            vendor_serializer.save()
                    except Vendor_model.DoesNotExist:
                        pass
                
                return Response({'status': status.HTTP_202_ACCEPTED, 'Response': "Updated successfully"}, status=status.HTTP_202_ACCEPTED)
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "Can't update data", "error": ser.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Delete User",
        operation_summary="Delete User",
        tags=['Admin','Vendor'],
        manual_parameters=
        [
            openapi.Parameter('email', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ]
    )
    def delete(self,request):
        email = request.query_params.get('email')
        try:
            if request.user.user_role != "Admin" or request.user.email == email:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "You don't have authencetation to update this account. Only a admin or a self can update there account."}, status=status.HTTP_400_BAD_REQUEST)

            user = User_model.objects.get(email=email)
            user.delete()
            return Response({'status':status.HTTP_200_OK,"message": "User deleted"}, status=status.HTTP_200_OK)
        except User_model.DoesNotExist:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class GetallUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get all User detail, Only Admin have this permission",
        operation_summary="All User Details",
        tags=['Admin', 'Vendor'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication"),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by email, first name, or last name (case-insensitive)")
        ]
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')

            if request.user.user_role in ['Admin', 'admin']:
                users = User_model.objects.exclude(user_role='Admin')
            elif request.user.user_role in ['Vendor', 'vendor']:
                users = User_model.objects.filter(user_role='Vendor')
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': "You can't have authentication to access for this."}, status=status.HTTP_200_OK)

            if search_query:
                users = users.filter(Q(email__icontains=search_query) | Q(username__icontains=search_query))

            ser = UserSerializer(users, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Get_ParticularUser(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get particular Teacher detail, only a Principle or Admin can access this",
        operation_summary="Principle Detail",
        tags=['Admin',"Vendor"],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication")
        ]
    )
    def get(self, request):
        email = request.query_params.get('email')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        

            ser = UserSerializer(user)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 

#API's from Items
class CreateItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
            operation_description="You can create a user as per roles like admin, vendor and user",
            operation_summary="Create User as per required fields",
            tags=['Item'],
            request_body=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    required=['email','password'],
                    properties={
                        'name':openapi.Schema(type=openapi.TYPE_STRING),
                        'description':openapi.Schema(type=openapi.TYPE_STRING),
                        'price':openapi.Schema(type=openapi.TYPE_NUMBER),
                        'quantity':openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                ),
            manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication")
            ]
        )
    def post(self,request):
        try:
            input_data = request.data
                
            print("input_data",input_data)
            input_data['name'] = input_data['name'].lower()
            serializers = ItemSerializer(data=input_data)
            if serializers.is_valid():
                serializers.save()

                return Response({'status':status.HTTP_201_CREATED,'response':'Item created successfully'},status=status.HTTP_201_CREATED)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Item can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,'response':e},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update User details",
        operation_summary="User Update",
        tags=['Item'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'name':openapi.Schema(type=openapi.TYPE_STRING),
                'description':openapi.Schema(type=openapi.TYPE_STRING),
                'price':openapi.Schema(type=openapi.TYPE_NUMBER),
                'quantity':openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        ),
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Enter id of item"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication")
        ]
    )
    def put(self, request):
        id = request.query_params.get('id')

        try:
            try:
                user = Items_model.objects.get(id=id)
            except Items_model.DoesNotExist:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "Item not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            input_data = request.data
            print(input_data)
            
            # Update user data
            ser = ItemSerializer(user, data=input_data, partial=True)
            if ser.is_valid():
                ser.save()
                
                return Response({'status': status.HTTP_202_ACCEPTED, 'Response': "Updated successfully"}, status=status.HTTP_202_ACCEPTED)
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "Can't update data", "error": ser.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Delete Item",
        operation_summary="Delete Item",
        tags=['Item'],
        manual_parameters=
        [
            openapi.Parameter('id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Enter id of item"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ]
    )
    def delete(self,request):
        id = request.query_params.get('id')
        try:
            user = Items_model.objects.get(id=id)
            user.delete()
            return Response({'status':status.HTTP_200_OK,"message": "Item deleted"}, status=status.HTTP_200_OK)
        except Items_model.DoesNotExist:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Item not found"}, status=status.HTTP_404_NOT_FOUND)

class GetallItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get all Item detail, Only Admin have this permission",
        operation_summary="All Item Details",
        tags=['Item'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication"),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by email, first name, or last name (case-insensitive)")
        ]
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')

            item_obj = Items_model.objects.all()
            
            if search_query:
                item_obj = item_obj.filter(Q(name__icontains=search_query) | Q(price__icontains=search_query))

            ser = ItemSerializer(item_obj, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Get_ParticularItem(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get particular Teacher detail, only a Principle or Admin can access this",
        operation_summary="Principle Detail",
        tags=['Item'],
        manual_parameters=[
            openapi.Parameter('id',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication")
        ]
    )
    def get(self, request):
        id = request.query_params.get('id')
        try:
            try:
                item = Items_model.objects.get(id=id)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': 'Item not found'}, status=status.HTTP_400_BAD_REQUEST)
        

            ser = ItemSerializer(item)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 

#API's for Purchase Order
class Create_PurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new purchase order",
        operation_summary="Create a new purchase order",
        tags=['Purchase'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['vendor', 'items'],
            properties={
                'vendor': openapi.Schema(type=openapi.TYPE_STRING,description="Enter the email id for the vendor"),
                'items': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_INTEGER),
                    description="Enter id's for Items"
                ),
                "delivery_date":openapi.Schema(type=openapi.TYPE_STRING,description="Enter the date of delivery i.e. YYYY-MM-DD HH:MM:SS"),
            }
        ),
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication")
        ]
    )
    def post(self, request):
        try:
            input_data = request.data
            vendor_user = Vendor_model.objects.get(user__email=input_data['vendor'])

            input_data['delivery_date'] = datetime.strptime(input_data['delivery_date'], '%Y-%m-%d %H:%M:%S')

            print(input_data['delivery_date'])

            last_po_number = Purchase_order_model.objects.last().po_number if Purchase_order_model.objects.exists() else None
        
            if last_po_number:
                last_po_number_numeric = int(re.search(r'\d+', last_po_number).group())
                print("last_po_number_numeric",last_po_number_numeric)
                group_po_number =re.search(r"^\D+", last_po_number).group()
                next_po_number = f'{group_po_number}{last_po_number_numeric + 1}'
                print("next_po_number",next_po_number)
            else:
                next_po_number = 'PO-1'
                print("next_po_number",next_po_number)
            

            po_obj = Purchase_order_model.objects.create(po_number=next_po_number,vendor=vendor_user,delivery_date = input_data['delivery_date'],quantity=0)
            total_po_quantity = 0
            for item_id in input_data['items']:
                try:
                    iteam_obj = Items_model.objects.get(id=item_id)
                    total_po_quantity += iteam_obj.quantity
                    po_obj.items.add(iteam_obj)
                except Items_model.DoesNotExist:
                    return Response({'status': status.HTTP_201_CREATED, 'response': 'All Items are not be created'}, status=status.HTTP_201_CREATED)

            print(total_po_quantity,"\n",po_obj)
            po_obj.quantity = total_po_quantity
            po_obj.save()

            return Response({'status': status.HTTP_201_CREATED, 'response': 'Purchase order placed successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Vendor_model.DoesNotExist:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': "vendor email is not valid, please check the email for vendor"}, status=status.HTTP_400_BAD_REQUEST)
        

class GetallPurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get all Item detail, Only Admin have this permission",
        operation_summary="All Item Details",
        tags=['Purchase'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication"),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by email, first name, or last name (case-insensitive)")
        ]
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')

            purchase_obj = Purchase_order_model.objects.all()
            
            if search_query:
                purchase_obj = purchase_obj.filter(Q(name__icontains=search_query) | Q(price__icontains=search_query))

            ser = PurchaseOrderSerializer(purchase_obj, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Get_ParticularPurchaseOrder(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get particular Teacher detail, only a Principle or Admin can access this",
        operation_summary="Principle Detail",
        tags=['Purchase'],
        manual_parameters=[
            openapi.Parameter('po_number',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter po_number to get purchase order details"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication")
        ]
    )
    def get(self, request):
        po_number = request.query_params.get('po_number')
        try:
            try:
                po_obj = Purchase_order_model.objects.get(po_number=po_number)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': f'No purchase order not found by po_number {po_number}'}, status=status.HTTP_400_BAD_REQUEST)
        

            ser = PurchaseOrderSerializer(po_obj)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 

class DeleteItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Delete purchase order",
        operation_summary="Delete purchase order",
        tags=['Purchase'],
        manual_parameters=
        [
            openapi.Parameter('po_number',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter po_number to get purchase order details"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ]
    )
    def delete(self,request):
        po_number = request.query_params.get('po_number')
        try:
            po_obj = Purchase_order_model.objects.get(po_number=po_number)
            po_obj.delete()
            return Response({'status':status.HTTP_200_OK,"message": "Purchase order deleted"}, status=status.HTTP_200_OK)
        except Items_model.DoesNotExist:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": f'No purchase order not found by po_number {po_number}'}, status=status.HTTP_404_NOT_FOUND)
