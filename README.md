
****** Description ******

In this project, a multi user blog was built, where users can sign in and post blog posts as well as 'Like' and 'Comment' on other posts made on the blog.
The posts have Edit and Delete functions.
This blog was hosted on Google App Engine and also, an authentication system was created for users to be able to register and sign in and then create blog posts.

****** How to Run *******

The blog can be accessed in this link
https://blog-10010.appspot.com/

**** To update and run in Google App Engine: *****
   gcloud app deploy --verbosity=info
   gcloud app browse

**** To run on local machine: ****
dev_appserver.py app.yaml

***** To clear local db: ****
dev_appserver.py --clear_datastore=yes .

**** To view local db: *****
http://localhost:8000/datastore?kind=TableName

********* To view db on google app engine: ***************
https://console.cloud.google.com/datastore/entities/query?project=blog-10010&ns=&kind=Comment&gql=
