# Catalog App
## The app is deployed on heroku on [Catalog App](https://sports-catalog-app.herokuapp.com/)

**What you need:**
 >The linux VM

 >Vagrant installed on the VM

 >Python 2 or Python 3 installed

 >A web browser
 
 >Postman installed for the API calls


**How to use this:**
 >From the terminal navigate to the location of the project

 >Type vagrant up

 >Type vagrant ssh

 >cd into /vagrant

 >Add the code folder inside the vagrant folder on the VM

 >cd into the directory where the code is, which should be inside the VM

 >Type python database_setup.py, this will intilise the database called 
 "catalog.db"

 >Type python catalog.py, this will deploy the application on your 
 localhost:5000

>From the web browser, open the [catalog-app](http://localhost:5000) 
to open the application


**For the API calls:**
>Open postman

>Input the url of the API method for example http://localhost:5000/users 
which is the API call to create a user 

>In the request body choose the type 'raw' and input the request body data
for example: 
```json
{
"email": "your_email",
"password": "your_password",
"name" :"your_name",
"picture": "your_picture"
}
```

>'Please update the data with your actual values'

>You can use the user you created to access the url 
[/resource](http://localhost:5000/resource) to test the login required 
functionality