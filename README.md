# Vendor-Management-System
A system for  Vendor Management System using Django and Django REST Framework. This system will handle vendor profiles, track purchase orders, and calculate vendor performance metrics.

*If pip is not in your system, Install it for Python offical website with python version above 3.9*

*if virutalenv not installed in system or getting error, install it using following command*
    `pip install virtualenv`

1. (Optional) SetUp a virtual environment :
    - For Windows : 
        `python -m venv virtualenv_name`
    
    - For mac :
        `python3 -m venv virtualenv_name`
    
    - For Linux :
        `virtualenv virtualenv_name`

2. *(If setup a environment)* Activate virtual environment:

    - For Windows : 
        `./virtualenv_name/Script/activate`
    
    - For mac :
        `source virtualenv_name/bin/activate`
    
    - For Linux :
        `source virtualenv_name/bin/activate`
      
3. *Install Requirements* :
    - For Windows : 
        `pip install -r requirments.txt`
    
    - For mac :
        `pip3 install -r requirments.txt`
    
    - For Linux :
        `pip install -r requirments.txt`
      
4. *Go into project folder*:
    - For Windows :
        `cd /vms`
    
    - For mac :
        `cd /vms`
    
    - For Linux :
        `cd /vms`
      
5. To Run the application
    
    - For Windows : 
        `python manage.py runserver`
    
    - For mac :
        `python3 manage.py runserver`
    
    - For Linux :
        `python manage.py runserver`


*when you application run successfully*, You can start with creating a admin first to create a vendor.

*For authentication* login to you account with Userlogin API, From this api you will get an access token with you can user for authentication

* In this there is role for `Admin` and `Vendor`.
* An Admin have access to get all user details, can create a vendor and to delete a user with access to other api
* A vendor can't register itself.
  
*Below is the description for metrics that is calculated for a vendor performace*

`On-Time Delivery Rate`

● Calculated each time a PO status changes to 'completed'.
● Logic: Count the number of completed POs delivered on or before
delivery_date and divide by the total number of completed POs for that vendor.

`Quality Rating Average`

● Updated upon the completion of each PO where a quality_rating is provided.
● Logic: Calculate the average of all quality_rating values for completed POs of
the vendor.

`Average Response Time`

● Calculated each time a PO is acknowledged by the vendor.
● Logic: Compute the time difference between issue_date and
acknowledgment_date for each PO, and then find the average of these times
for all POs of the vendor.

`Fulfilment Rate`
● Calculated upon any change in PO status.
● Logic: Divide the number of successfully fulfilled POs (status 'completed'
without issues) by the total number of POs issued to the vendor.



