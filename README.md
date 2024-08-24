# attention-api

Make sure to have GOOGLE_APPLICATION_CREDENTIALS environment variable point to the JSON file that stores the service 
account key to the Firebase project

The first time you run the server, you will need to apply migrations: `python manage.py migrate`

To put test users in the database, use `python manage.py dbshell` to get an interactive shell in the current database. If you don't have the CLI interface on the path, you can use `python manage.py shell` and interact with the ORM through Django's API.
To create a simple test account, run `python manage.py shell --command="from django.contrib.auth import get_user_model; get_user_model().objects.create_user(first_name='random', last_name='person', username='test', password='password', email='random@aracroproducts.com')"`

To run the development server, run `python manage.py runserver`. See the [Django Docs](https://docs.djangoproject.com/en/5.1/) for more information
