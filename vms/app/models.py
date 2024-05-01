from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin,BaseUserManager
# Create your models here.


class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            raise ValueError("Please enter an email address")
        email = self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self,email=None,password=None,**extra_fields):
         extra_fields.setdefault('is_staff',False)
         extra_fields.setdefault('is_superuser',False)
         return self._create_user(email,password,**extra_fields)

    def create_superuser(self,email=None,password=None,**extra_fields):
         extra_fields.setdefault('is_staff',True)
         extra_fields.setdefault('is_superuser',True)
         return self._create_user(email,password,**extra_fields)

class User_model(AbstractBaseUser,PermissionsMixin):
    User_Role=(
        ('Admin','admin'),
        ('Vendor','vendor'),
        ('User','user'),
    )
    email=models.EmailField(max_length=256,unique=True)
    username=models.CharField(max_length=255,blank=True,null=True)
    password =models.CharField(max_length=255)
    phone = models.IntegerField(blank=True,null=True)
    address = models.CharField(max_length=300,blank=True,null=True)
    user_role = models.CharField(max_length=30,choices=User_Role)
    
    is_active=models.BooleanField(default=True)
    is_superuser=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    is_block = models.BooleanField(default=False)
    otp = models.IntegerField(blank=True,null=True)
    otp_created_at = models.DateTimeField(blank=True,null=True)
    otp_verified = models.BooleanField(default=False)
    
    objects=CustomUserManager()

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]
    
    def __str__(self):
        return f"{self.username} - {self.user_role}"


class Vendor_model(models.Model):
    user = models.OneToOneField(User_model,on_delete= models.CASCADE,related_name="vendor_user")
    contact_details = models.CharField(max_length=500,blank=True,null=True)
    code = models.CharField(max_length=15,unique=True)
    on_time_delivery_rate = models.FloatField()
    quality_rating_avg = models.FloatField()
    average_response_time = models.FloatField()
    fulfillment_rate = models.FloatField()

    def __str__(self):
        return f"{self.code} - {self.user.username}"
    
class Items_model(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField()
    
    def __str__(self):
        return {self.name}

class Purchase_order_model(models.Model):
    po_number = models.CharField(unique=True,max_length=15)
    vendor = models.ForeignKey(Vendor_model,on_delete=models.CASCADE,related_name="purchase_vendor")
    order_date = models.DateTimeField()
    delivery_date = models.DateTimeField()
    items = models.ManyToManyField(Items_model,related_name="purchase_items")
    quantity = models.IntegerField()
    status = models.CharField(max_length=50)
    quality_rating = models.FloatField(null=True)
    issue_date = models.DateTimeField()
    acknowledgment_date = models.DateTimeField(null=True)

    def __str__(self):
        return f"{self.po_number} - {self.vendor.user.username}"

class Performance_model(models.Model):
    vendor = models.ForeignKey(Vendor_model,on_delete=models.CASCADE)
    date = models.DateTimeField()
    on_time_delivery_rate = models.FloatField()
    quality_rating_avg = models.FloatField()
    average_response_time = models.FloatField()
    fulfillment_rate = models.FloatField()

    def __str__(self):
        return f"{self.vendor.user.username} - {self.date}"


