from django.shortcuts import render
from .models import *
from .serializers import *
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import login,logout
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
                if input_data['user_role'].lower()=='admin':
                    input_data['is_superuser']=True
                    input_data['is_staff']=True
                
                print("input_data",input_data)
                serializers = UserSerializer(data=input_data)
                if serializers.is_valid():
                    serializers.save()

                    return Response({'status':status.HTTP_201_CREATED,'response':'User creared successfully'},status=status.HTTP_201_CREATED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'User can not be created','error':serializers.errors},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password must contain a capital letter, lower letter, number and a special character'},status=status.HTTP_400_BAD_REQUEST)
            
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

            if user.is_block != True:
                if check_password(password,user.password): 
                    token=get_tokens_for_user(user)
                    print(request.user) 
                    request.session['access_token'] = token
                    request.session.save()    
                    login(request,user)
                    return Response({'status':status.HTTP_202_ACCEPTED,'response':'Logged In successfull','access_token':token},status=status.HTTP_202_ACCEPTED)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'response':'Password is incorrect'},status=status.HTTP_400_BAD_REQUEST)
            return Response({'status':status.HTTP_401_UNAUTHORIZED,"response":"User account is blocked"},status=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as e:
            return Response({'status':status.HTTP_404_NOT_FOUND,'response':'User not found, check you email'},status=status.HTTP_404_NOT_FOUND)

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
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "email not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            print(request.user.user_role)
            if request.user.user_role != "Admin" or request.user.user_role == user.user_role:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': "You don't have authencetation to update this account. Only a admin or a self can update there account."}, status=status.HTTP_400_BAD_REQUEST)

            input_data = request.data

            ser = UserSerializer(user, data=input_data, partial=True)
            if ser.is_valid():
                ser.save()
                return Response({'status': status.HTTP_202_ACCEPTED, 'Response': "updated successfully"}, status=status.HTTP_202_ACCEPTED)
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
    # pagination_classes = custompagination
    
    @swagger_auto_schema(
        operation_description="Get all User detail,Only Admin have this permission",
        operation_summary="All User Details",
        tags=['Admin',"Vendor"],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING, description="access token for Authentication"),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search users by email, first name, or last name (case-insensitive)")
        ]
    )
    def get(self, request):
        try:
            search_query = request.query_params.get('search', '')
            
            if request.user.user_role in ['Admin','admin']:
                users = User_model.objects.all().exclude(role='organizer')
                
            elif request.user.role in ['Vendor','vendor']:
                users = User_model.objects.filter(role='player')

            else:
                return Response({'status': status.HTTP_400_BAD_REQUEST,'response':"You can't have authentication to access for this."}, status=status.HTTP_200_OK)

            # elif request.user.role in ['User','user']:
            #     users = User_model.objects.get(email=request.user.email)


            # Apply search filter if a search query is provided
            if search_query:
                users = users.filter(Q(email__icontains=search_query) | Q(firstname__icontains=search_query) | Q(lastname__icontains=search_query))

            # total_count = users.count()
            # paginator = self.pagination_classes()
            # users = paginator.paginate_queryset(queryset=users, request=request)

            ser = UserSerializer(users, many=True)
            return Response({'status': status.HTTP_200_OK, 'response': ser.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"response":f"An internal error occur {str(e)}"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
