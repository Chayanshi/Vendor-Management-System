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


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
    
def get_random_otp():
    randomotp = random.randint(0000, 9999)
    return randomotp 

class CreateUser(APIView):
   @swagger_auto_schema(
        operation_summary="Create user with specified roles like admin, vendor, or user",
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
        responses={
            201: "Created successfully",
            400: "Bad request",
            500: "Internal server error",
        }
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
                password = make_password(input_data['password'])
                
                input_data['password'] = password
                if input_data['user_role'].lower() =='admin':
                    print("admin created")
                    input_data['is_superuser']=True
                    input_data['is_staff']=True
                
                input_data['user_role'] = input_data['user_role'].capitalize()

                print("input_data",input_data)
                serializers = UserSerializer(data=input_data)
                print("serializer response",serializers)
                if serializers.is_valid():
                    serializers.save()

                    return Response({'status':status.HTTP_201_CREATED,'response':'User creared successfully'},status=status.HTTP_201_CREATED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'User can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password must contain a upper letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CreateVendor(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
            operation_summary="Create Vendor as per required details, only a admin can create vendor",
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
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING,default='Bearer ', description="access token for Authentication")
            ],
            responses={
                201: "Created successfully",
                400: "Bad request",
                401: "Unauthorized",
                500: "Internal server error",
            }
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
                
                if len(input_data['password']) < 8 :
                    return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password must be of 8 character'},status=status.HTTP_400_BAD_REQUEST)
           
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

class UserLogin(APIView):
    @swagger_auto_schema(
        operation_summary="Login to your account using email and password for authentication adn get access token",
        tags=['Admin','Vendor'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email','password'],
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING,default="vendor@mailinator.com"),
                'password':openapi.Schema(type=openapi.TYPE_STRING,default="Vendor@123")
            }
        ),
        responses={
            201: "Created successfully",
            400: "Bad request",
            404: "Unauthorized, when user is blocked",
            500: "Internal server error"
        }
    )
    def post(self,request):
        try:
            email=request.data.get('email')
            password=request.data.get('password')

            user = User_model.objects.get(email=email)

            user = authenticate(request, email=email, password=password)
            if user.is_block == False and user is not None :
                if check_password(password,user.password): 
                    token=get_tokens_for_user(user)
                    request.session['access_token'] = token
                    request.session.save()
                    user.is_active = True    
                    login(request,user)
                    return Response({'status':status.HTTP_202_ACCEPTED,'response':'Logged In successfull','access_token':token},status=status.HTTP_202_ACCEPTED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password is incorrect'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_401_UNAUTHORIZED,"response":"User account is blocked"},status=status.HTTP_401_UNAUTHORIZED)

        except User_model.DoesNotExist :
            print("error in doesnot exist",str(e))
            return Response({'status':status.HTTP_404_NOT_FOUND,'response':'User not found, check you email'},status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserLogout(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="User logout using auth token",
        tags=['Admin','Vendor'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING,default='Bearer '),
        ],
        response = {
            200: "Logout successfully",
            401: "Unauthorized",
            400: "Bad request. User not found",
            500: "Internal server error"
        }
    )
    def get(self,request):
        try:
            user=request.user
            user.is_active = False
            logout(request)
            return Response({'status':status.HTTP_200_OK,'Response':'logout successfuly'},status.HTTP_200_OK)
        except User_model.DoesNotExist:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':'user not found'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SendOTP(APIView):
    @swagger_auto_schema(
        operation_summary="To get verification otp on email.",
        tags=['Forgot Password'],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp")
        ],
        responses={
            200:"OTP sended succesfully",
            404:"User not found by given email",
            500:"Internal server error"
        }
    )
    def get(self, request):
        email = request.query_params.get('email')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"User not found"},status=status.HTTP_404_NOT_FOUND)
            
            otp=get_random_otp()
            print(otp)
            sendotp(otp=otp,email=email)
            user.otp = otp
            user.save()
            return Response({'status':status.HTTP_200_OK,'Response':"Check your email for otp"},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyOTP(APIView):
    @swagger_auto_schema(
        operation_description="Verify the sended OTP to user email. The otp is verifed till 3 min of when the otp is sended. If otp expires re-send otp.",
        operation_summary="OTP verification",
        tags=['Forgot Password'],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('OTP',openapi.IN_QUERY,type=openapi.TYPE_INTEGER,description="Enter verification otp, sended on your email")
        ],
        response={
            200:"Successfully verified email with OTP",
            400:"Bad request",
            404:"User not found by given email",
            500:"Internal server error"
        }
    )
    
    def get(self, request):
        email = request.query_params.get('email')
        entered_otp = request.query_params.get('OTP')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"email not found"},status=status.HTTP_404_NOT_FOUND)
            
            print('db',user.otp)
            print('user',entered_otp)
           
            if int(entered_otp) == user.otp and (timezone.now() - user.otp_created_at).seconds <=180:
                user.otp_verified = True
                user.save()
                return Response({'status':status.HTTP_200_OK,'Response':"Otp Verified"},status=status.HTTP_200_OK)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':"OTP is not valid, the OTP Valid period is 2 min"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
               
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
           
        ],
        response={
            200:"Successfully verified email with OTP",
            400:"Bad request",
            404:"User not found by given email",
            500:"Internal server error"
        }
    )
    def put(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        email = request.query_params.get('email')
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"email not found"},status=status.HTTP_404_NOT_FOUND)
            
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
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ChangePassword(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="After email verification with email user can change the password",
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
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email for whose password is getting changed"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication",default="Bearer ")
        ],
        response={
            200:"Succesfully changed password",
            400:"Bad request",
            401: "Unauthorized",
            404:"User not found by given email",
            500:"Internal server error"
        }
    )
    def put(self,request):
        password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
        email = request.query_params.get('email')
        # email = request.user
        try:
            try:
                user = User_model.objects.get(email=email)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,'Response':"email not found"},status=status.HTTP_404_NOT_FOUND)
             
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
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
         
class UpdateUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Update user details",
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
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            202: "Updated data successfully",
            400: "Bad request",
            401: "Unauthorized",
            404: "User not found by given email",
            500: "Internal server error"
        }
    )
    def put(self, request):
        email = request.query_params.get('email')

        try:
            try:
                user = User_model.objects.get(email=email)
            except User_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            input_data = request.data
            print(input_data)
            
            user_data = {k: v for k, v in input_data.items() if k not in ['contact_details', 'on_time_delivery_rate', 'quality_rating_avg', 'average_response_time', 'fulfillment_rate']}
            vendor_data = {k: v for k, v in input_data.items() if k in ['contact_details', 'on_time_delivery_rate', 'quality_rating_avg', 'average_response_time', 'fulfillment_rate']}

            # Update user data
            ser = UserSerializer(user, data=user_data, partial=True)
            if ser.is_valid():
                user_instance = ser.save()

                if user_instance.user_role.lower() == 'vendor':
                    try:
                        vendor_instance = user_instance.vendor_user
                        vendor_serializer = VendorSerializer(vendor_instance, data=vendor_data, partial=True)
                        if vendor_serializer.is_valid():
                            vendor_serializer.save()
                    except VendorModel.DoesNotExist:
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
        operation_summary="Delete a user",
        tags=['Admin','Vendor'],
        manual_parameters=
        [
            openapi.Parameter('email', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING,default="Bearer "),
        ],
        responses={
            200: "Deleted data successfully",
            400: "Bad request",
            401: "Unauthorized",
            404: "User not found by given email",
            500: "Internal server error"
        }
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
            return Response({'status':status.HTTP_404_NOT_FOUND,"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetallUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="Get all user details",
        tags=['Admin', 'Vendor'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer "),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by email, user name"),
            openapi.Parameter('user_role', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search by user role")
        ],
        responses={
            200: "Successfully get all data",
            400: "Bad request",
            401: "Unauthorized",
            500: "Internal server error"
        }
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')
            role = request.query_params.get('user_role', '')

            if request.user.user_role in ['Admin', 'admin']:
                users = User_model.objects.exclude(user_role='Admin')
            elif request.user.user_role in ['Vendor', 'vendor']:
                users = User_model.objects.filter(user_role='Vendor')
            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'response': "You can't have authentication to access for this."}, status=status.HTTP_200_OK)

            if search_query:
                users = users.filter(Q(email__icontains=search_query) | Q(username__icontains=search_query))
            if role:
                users = users.filter(Q(user_role__icontains=role) | Q(user_role__icontains=role))

            ser = UserSerializer(users, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Get_ParticularUser(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Get details of a particular user",
        tags=['Admin',"Vendor"],
        manual_parameters=[
            openapi.Parameter('email',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email of user"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Successfully got all data",
            400: "Bad request",
            401: "Unauthorized",
            404: "User not found by given email",
            500: "Internal server error"
        }
    )
    def get(self, request):
        email = request.query_params.get('email')
        try:
            user = User_model.objects.get(email=email)

            ser = UserSerializer(user)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        
        except User_model.DoesNotExist :
             return Response({'status': status.HTTP_404_NOT_FOUND, 'response': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
 
class CreateItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
            operation_summary="Create a item as per required fields",
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
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
            ],
            responses={
                201: "Created successfully",
                400: "Bad request",
                401: "Unauthorized",
                500: "Internal server error"
            }
        )
    def post(self,request):
        try:
            input_data = request.data
                
            print("input_data",input_data)
            input_data['name'] = input_data['name'].lower()
            serializers = ItemSerializer(data=input_data)
            if serializers.is_valid():
                serializers.save()

                return Response({'status':status.HTTP_201_CREATED,'response':'Item created successfully',"item_id":serializers.data.get("id")},status=status.HTTP_201_CREATED)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Item can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,'response':e},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Update item data",
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
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            202: "Updated data successfully",
            400: "Bad request",
            401: "Unauthorized",
            404: "Item not found",
            500: "Internal server error"
        }
    )
    def put(self, request):
        id = request.query_params.get('id')

        try:
            user = ItemsModel.objects.get(id=id)
            
            input_data = request.data
            print(input_data)
            
            ser = ItemSerializer(user, data=input_data, partial=True)
            if ser.is_valid():
                ser.save()
                
                return Response({'status': status.HTTP_202_ACCEPTED, 'Response': "Updated successfully"}, status=status.HTTP_202_ACCEPTED)
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "Can't update data", "error": ser.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        
        except ItemsModel.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': "Item not found"}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Delete a Item",
        tags=['Item'],
        manual_parameters=
        [
            openapi.Parameter('id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Enter id of item"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        responses={
            200: "Deleted successfully",
            401: "Unauthorized",
            404: "User not found by given email",
            500: "Internal server error"
        }
    )
    def delete(self,request):
        id = request.query_params.get('id')
        try:
            user = ItemsModel.objects.get(id=id)
            user.delete()
            return Response({'status':status.HTTP_200_OK,"message": "Item deleted"}, status=status.HTTP_200_OK)
        except ItemsModel.DoesNotExist:
            return Response({'status':status.HTTP_404_NOT_FOUND,"message": "Item not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetallItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get all Item detail, Only Admin have this permission",
        operation_summary="All Item Details",
        tags=['Item'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication"),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by name, price, or quantity")
        ],
        responses={
            200: "Succesfully got all details",
            401: "Unauthorized",
            500: "Internal server error"
        }
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')

            item_obj = ItemsModel.objects.all()
            
            if search_query:
                item_obj = item_obj.filter(Q(name__icontains=search_query) | Q(price__icontains=search_query) | Q(quantity__icontains=search_query))

            ser = ItemSerializer(item_obj, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Get_ParticularItem(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Get a particular item detail by item id",
        tags=['Item'],
        manual_parameters=[
            openapi.Parameter('id',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter email to get verification otp"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Succefully got a item detail",
            404: "Item not found with given id",
            401: "Unauthorized",
            500: "Internal server error"
        }
    )
    def get(self, request):
        id = request.query_params.get('id')
        try:
            item = ItemsModel.objects.get(id=id)

            ser = ItemSerializer(item)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)

        except ItemsModel.DoesNotExist :
            return Response({'status': status.HTTP_404_NOT_FOUND, 'response': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Create_PurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Create a purchase order",
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
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            201: "Created purchase order successfully",
            401: "Unauthorized",
            404: "Vendor not found by given email",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            input_data = request.data
            vendor_user = VendorModel.objects.get(user__email=input_data['vendor'])

            input_data['delivery_date'] = datetime.strptime(input_data['delivery_date'], '%Y-%m-%d %H:%M:%S')

            print(input_data['delivery_date'])

            last_po_number = PurchaseOrderModel.objects.last().po_number if PurchaseOrderModel.objects.exists() else None
        
            if last_po_number:
                last_po_number_numeric = int(re.search(r'\d+', last_po_number).group())
                print("last_po_number_numeric",last_po_number_numeric)
                group_po_number =re.search(r"^\D+", last_po_number).group()
                next_po_number = f'{group_po_number}{last_po_number_numeric + 1}'
                print("next_po_number",next_po_number)
            else:
                next_po_number = 'PO-1'
                print("next_po_number",next_po_number)
            

            po_obj = PurchaseOrderModel.objects.create(po_number=next_po_number,vendor=vendor_user,delivery_date = input_data['delivery_date'],quantity=0)
            total_po_quantity = 0
            for item_id in input_data['items']:
                try:
                    iteam_obj = ItemsModel.objects.get(id=item_id)
                    total_po_quantity += iteam_obj.quantity
                    po_obj.items.add(iteam_obj)
                except ItemsModel.DoesNotExist:
                    return Response({'status': status.HTTP_201_CREATED, 'response': 'All Items are not be created',"item_id":item_id}, status=status.HTTP_201_CREATED)

            print(total_po_quantity,"\n",po_obj)
            po_obj.quantity = total_po_quantity
            po_obj.save()

            return Response({'status': status.HTTP_201_CREATED, 'response': 'Purchase order placed successfully','po_number':po_obj.po_number}, status=status.HTTP_201_CREATED)

        except VendorModel.DoesNotExist:
            return Response({'status': status.HTTP_404_NOT_FOUND, 'response': "vendor email is not valid, please check the email for vendor"}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class GetallPurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="Get details for all purchase order and search by ",
        tags=['Purchase'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer "),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by po_number"),
            openapi.Parameter('status', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search by status")
        ],
        responses={
            200: "Successfully got all purchase orders",
            401: "Unauthorized",
            500: "Internal server error"
        }
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')
            status_query = request.query_params.get('status', '')

            purchase_obj = PurchaseOrderModel.objects.all()
            
            if search_query:
                purchase_obj = purchase_obj.filter(Q(po_number__icontains=search_query))
            if status_query:
                purchase_obj = purchase_obj.filter(Q(status__icontains=status_query))

            ser = PurchaseOrderSerializer(purchase_obj, many=True)

            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Get_ParticularPurchaseOrder(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Get particular purchase order by po_number",
        tags=['Purchase'],
        manual_parameters=[
            openapi.Parameter('po_number',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter po_number to get purchase order details"),
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Successfully get a purchase order detail",
            401: "Unauthorized",
            404: "User not found by given email",
            500: "Internal server error"
        }
    )
    def get(self, request):
        po_number = request.query_params.get('po_number')
        try:
            po_obj = PurchaseOrderModel.objects.get(po_number=po_number)
    
            ser = PurchaseOrderSerializer(po_obj)
            
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        
        except PurchaseOrderModel.DoesNotExist :
                return Response({'status': status.HTTP_404_NOT_FOUND, 'response': f'No purchase order not found by po_number {po_number}'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdatePurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Update a purchase order",
        tags=['Purchase'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'status':openapi.Schema(type=openapi.TYPE_STRING,description="The status wil be completed, pending, or canceled"),
                'quality_rating':openapi.Schema(type=openapi.TYPE_NUMBER),
                'delivery_date':openapi.Schema(type=openapi.TYPE_STRING,description="Enter the date of delivery i.e. YYYY-MM-DD HH:MM:SS"),
                'issue_date':openapi.Schema(type=openapi.TYPE_STRING,description="Enter the date of issue to vendor i.e. YYYY-MM-DD HH:MM:SS"),
                'actual_delivered_date':openapi.Schema(type=openapi.TYPE_STRING,description="Enter the actual delivered date of issue to vendor i.e. YYYY-MM-DD HH:MM:SS"),
            }
        ),
        manual_parameters=[
            openapi.Parameter('po_number', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Enter po_number of purchase item"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            202: "Updated data successfully",
            400: "Bad request",
            401: "Unauthorized",
            404: "Purchase order not found with given po_number",
            500: "Internal server error"
        }
    )
    def put(self, request):
        try:
            po_number = request.query_params.get('po_number')

            try:
                po_obj = PurchaseOrderModel.objects.get(po_number=po_number)
            except PurchaseOrderModel.DoesNotExist:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': f"Order not found by po_number {po_number}"}, status=status.HTTP_400_BAD_REQUEST)
            
            input_data = request.data
            if input_data.get('status'):
                input_data['status'] = input_data['status'].lower()
            
            serializer = PurchaseOrderSerializer(po_obj, data=input_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'status': status.HTTP_202_ACCEPTED, 'Response': "Updated successfully"}, status=status.HTTP_202_ACCEPTED)
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "Can't update data", "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeletePurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Delete a purchase order",
        tags=['Purchase'],
        manual_parameters=
        [
            openapi.Parameter('po_number',openapi.IN_QUERY,type=openapi.TYPE_STRING,description="Enter po_number to get purchase order details"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING,default="Bearer "),
        ],
        responses={
            200: "Deleted successfully",
            401: "Unauthorized",
            404: "Purchase order not found with given po_number",
            500: "Internal server error"
        }
    )
    def delete(self,request):
        po_number = request.query_params.get('po_number')
        try:
            po_obj = PurchaseOrderModel.objects.get(po_number=po_number)
            po_obj.delete()
            return Response({'status':status.HTTP_200_OK,"message": "Purchase order deleted"}, status=status.HTTP_200_OK)
        except ItemsModel.DoesNotExist:
            return Response({'status':status.HTTP_404_NOT_FOUND,"message": f'No purchase order not found by po_number {po_number}'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'response': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AcknowledgePurchaseOrder(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="To acknowledge a purchase order by vendor",
        tags=['Purchase'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Got data successfully",
            401: "Unauthorized",
            404: "Purchase order not found with given email",
            500: "Internal server error"
        }
    )
    def post(self,request,po_number):
        try:
            purchase_order = PurchaseOrderModel.objects.get(po_number=po_number)

            now = datetime.now()
            print('now.strftime("%Y-%m-%d %H:%M:%S")',now.strftime("%Y-%m-%d %H:%M:%S"))
            purchase_order.acknowledgment_date = now.strftime("%Y-%m-%d %H:%M:%S")
            purchase_order.save()

            return Response({'status': status.HTTP_200_OK, 'message': 'Purchase order acknowledged successfully'}, status=status.HTTP_200_OK)

        except PurchaseOrderModel.DoesNotExist:
            return Response({'status': status.HTTP_404_NOT_FOUND, 'message': 'Purchase order not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Get_VendorPerformance(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get a vendor performace ",
        tags=['Vendor'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Got data successfully",
            401: "Unauthorized",
            404: "Vendor not found with given vendor code",
            500: "Internal server error"
        }
    )
    def get(self,request,code):
        try:
            vendor_instance = VendorModel.objects.get(code=str(code))

            data = {
                "on_time_delivery_rate":vendor_instance.on_time_delivery_rate,
                "quality_rating_avg":vendor_instance.quality_rating_avg,
                "average_response_time":vendor_instance.average_response_time,
                "fulfillment_rate":vendor_instance.fulfillment_rate
            }

            return Response({'status':status.HTTP_200_OK,"vendor_code":code,"response":data},status=status.HTTP_200_OK)
        except VendorModel.DoesNotExist:
            return Response({'status': status.HTTP_404_NOT_FOUND, 'message': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetHistoricalRecord(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get historical records metrices as per month and year",
        tags=['Historical Record'],
        manual_parameters=[
            openapi.Parameter('month', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description="Enter month number for which you want record. eg: 1 for jan"),
            openapi.Parameter('year', openapi.IN_QUERY, type=openapi.TYPE_INTEGER,description="Enter year for which you want record. eg: 2024"),
            openapi.Parameter('vendor_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER,description="Enter vendor id"),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication",default="Bearer ")
        ],
        responses={
            200: "Got data successfully",
            401: "Unauthorized",
            404: "Vendor not found with given vendor code",
            500: "Internal server error"
        }
    )
    def get(self,request):
        try:
            id = request.query_params.get('vendor_id')
            month = request.query_params.get('month')
            year = request.query_params.get('year')

            vendor_instance = VendorModel.objects.get(id=int(id))
            print(vendor_instance,month,year)
            data = {}
            if month and year:
                historical_record = HistoricalPerformanceModel.objects.get(vendor=vendor_instance,month=month,year=year)
                data = {
                    "on_time_delivery_rate":historical_record.on_time_delivery_rate,
                    "quality_rating_avg":historical_record.quality_rating_avg,
                    "average_response_time":historical_record.average_response_time,
                    "fulfillment_rate":historical_record.fulfillment_rate
                }
                return Response({'status':status.HTTP_200_OK,"vendor_email":vendor_instance.user.email,"month":month,"year":year,"response":data},status=status.HTTP_200_OK)
            
            historical_record = HistoricalPerformanceModel.objects.filter(vendor=vendor_instance)
            for records in historical_record:
                data[f"{records.month}/{records.year}"] = {
                    "on_time_delivery_rate":records.on_time_delivery_rate,
                    "quality_rating_avg":records.quality_rating_avg,
                    "average_response_time":records.average_response_time,
                    "fulfillment_rate":records.fulfillment_rate
                }
                
            return Response({'status':status.HTTP_200_OK,"vendor_email":vendor_instance.user.email,"response":data},status=status.HTTP_200_OK)
            
        except HistoricalPerformanceModel.DoesNotExist:
            return Response({'status': status.HTTP_404_NOT_FOUND, 'message': 'Historical record not found for given month/year and vendor'}, status=status.HTTP_404_NOT_FOUND)
        except VendorModel.DoesNotExist:
            return Response({'status': status.HTTP_404_NOT_FOUND, 'message': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
