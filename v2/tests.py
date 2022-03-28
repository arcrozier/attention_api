import random
from typing import Final

from django.contrib.auth.models import User
from django.db import models
from django.test import Client
from django.test import TestCase
from rest_framework.authtoken.models import Token

from v2.models import FCMTokens, Friend
from v2.views import check_params

# Create your tests here.

auth_required_post_endpoints = ['send_alert', 'register_device', 'add_friend', 'alert_read']
auth_required_get_endpoints = ['get_name', 'get_info']
auth_required_delete_endpoints = ['delete_friend']
auth_required_put_endpoints = ['edit']


class APIV2TestSuite(TestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='my_password')
        self.user2 = User.objects.create_user(username='user2', password='my_password2', first_name='will', last_name='smith')
        Friend.objects.create(owner=self.user2, friend=self.user1, sent=3)
        self.token1 = Token.objects.create(user=self.user1)
        self.token2 = Token.objects.create(user=self.user2)

    def test_add_user_simple(self):
        """
        This should test upload_public_key
        Use both POST and PUT
        Add a user, update it, make sure a new one wasn't created
        Check status codes
        """
        c = Client()
        self.assertEqual(User.objects.count(), 2)
        response = c.post('/v2/register_user/', {'username': 'user3', 'password': 'my_password3', 'first_name':
                                                 'joe', 'last_name': 'blow'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 3)
        user1 = User.objects.get(username='user1')
        user2 = User.objects.get(username='user2')
        user3 = User.objects.get(username='user3')
        self.assertEqual(user1.first_name, '')
        self.assertEqual(user1.last_name, '')
        self.assertEqual(user1.email, '')
        self.assertEqual(user2.first_name, 'will')
        self.assertEqual(user2.last_name, 'smith')
        self.assertEqual(user2.email, '')
        self.assertEqual(user3.first_name, 'joe')
        self.assertEqual(user3.last_name, 'blow')
        self.assertEqual(user3.email, '')

        response = c.post('/v2/register_user/', {'username': 'user4', 'password': 'my_password4', 'first_name':
                                                 'john', 'last_name': 'dohn'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 4)
        user1 = User.objects.get(username='user1')
        user2 = User.objects.get(username='user2')
        user3 = User.objects.get(username='user3')
        user4 = User.objects.get(username='user4')
        self.assertEqual(user1.first_name, '')
        self.assertEqual(user1.last_name, '')
        self.assertEqual(user1.email, '')
        self.assertEqual(user2.first_name, 'will')
        self.assertEqual(user2.last_name, 'smith')
        self.assertEqual(user2.email, '')
        self.assertEqual(user3.first_name, 'joe')
        self.assertEqual(user3.last_name, 'blow')
        self.assertEqual(user3.email, '')
        self.assertEqual(user4.first_name, 'john')
        self.assertEqual(user4.last_name, 'dohn')
        self.assertEqual(user4.email, '')

        response = c.post('/v2/register_user/', {'username': 'user5', 'password': 'my_password5', 'first_name':
                                                 'sean', 'last_name': 'bean', 'email': 'valid_email@example.com'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 5)
        user1 = User.objects.get(username='user1')
        user2 = User.objects.get(username='user2')
        user3 = User.objects.get(username='user3')
        user4 = User.objects.get(username='user4')
        self.assertEqual(user1.first_name, '')
        self.assertEqual(user1.last_name, '')
        self.assertEqual(user1.email, '')
        self.assertEqual(user2.first_name, 'will')
        self.assertEqual(user2.last_name, 'smith')
        self.assertEqual(user2.email, '')
        self.assertEqual(user3.first_name, 'joe')
        self.assertEqual(user3.last_name, 'blow')
        self.assertEqual(user3.email, '')
        self.assertEqual(user4.first_name, 'john')
        self.assertEqual(user4.last_name, 'dohn')
        self.assertEqual(user4.email, 'valid_email@example.com')

    def test_add_user_weird(self):
        """
        Test malformed requests (missing required parameters, too many parameters, etc.)
        """
        c = Client()
        response = c.post('/v2/register_user/', {'username': 'user2', 'password': 'my_password3',
                                                 'first_name': 'joe', 'last_name': 'blow'})
        self.assertContains(response, '', status_code=400)
        self.assertEqual(User.objects.get(username='user2').first_name, 'will')
        self.assertEqual(User.objects.get(username='user2').last_name, 'smith')

        response = c.post('/v2/register_user/', {'username': 'user3', 'password': 'my_password3',
                                                 'first_name': 'joe', 'last_name': 'blow', 'email': 'invalid_email'})
        self.assertContains(response, '', status_code=400)
        self.assertFalse(User.objects.filter(username='user3').exists())

        response = c.post('/v2/register_user/', {'username': 'user3', 'password': 'my_password3',
                                                 'first_name': 'joe', 'last_name': 'blow',
                                                 'email': 'invalid_email@gmail'})
        self.assertContains(response, '', status_code=400)
        self.assertFalse(User.objects.filter(username='user3').exists())

        response = c.post('/v2/register_user/', {'username': 'user3',
                                                 'first_name': 'joe', 'last_name': 'blow',
                                                 'email': 'valid_email@gmail.com'})
        self.assertContains(response, '', status_code=400)
        self.assertFalse(User.objects.filter(username='user3').exists())

        response = c.put('/v2/register_user/', {'id': 'user1', 'token': 'Updated2'},
                         content_type='application/json')
        self.assertContains(response, '', status_code=404)
        response = c.post('/v2/register_user/')
        self.assertContains(response, '', status_code=400)
        response = c.get('v2/register_user/', {'username': 'user3', 'password': 'my_password3',
                                               'first_name': 'joe', 'last_name': 'blow'})
        self.assertContains(response, '', status_code=404)

    def test_register_device(self):
        c = Client()
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'})
        self.assertContains(response, '', status_code=403)
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(FCMTokens.objects.get(username='user1').fcm_token, 'fake_token')
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)
        self.assertEqual(FCMTokens.objects.get(username='user1').fcm_token, 'fake token')

    def test_add_friend(self):
        # Test undeleting a friend doesn't reset sent/received fields
        c = Client()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=200)
        friend: Friend = Friend.objects.get(owner__username='user1', friend__username='user2')
        self.assertFriendEqual(friend,
                               Friend(pk=friend.pk, owner=self.user1, friend=self.user2, sent=0, received=0,
                                      deleted=False))
        friend.sent = 1
        friend.received = 2
        friend.save()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        friend = Friend.objects.get(owner__username='user1', friend__username='user2')
        self.assertFriendEqual(friend,
                               Friend(pk=friend.pk, owner=self.user1, friend=self.user2, sent=1, received=2,
                                      deleted=False))
        friend.deleted = True
        friend.save()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=200)
        friend = Friend.objects.get(owner__username='user1', friend__username='user2')
        self.assertFriendEqual(friend,
                               Friend(pk=friend.pk, owner=self.user1, friend=self.user2, sent=1, received=2,
                                      deleted=False))

        # Check that user1 adding user4 as a friend does not add user1 as a friend of user4
        # i.e. user1 -> user4, but user4 !-> user1
        user4 = User.objects.create_user(username='user4', password='my_password4', first_name='will',
                                         last_name='smith')
        response = c.post('/v2/add_friend/', {'username': 'user4'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=200)
        friend: Friend = Friend.objects.get(owner__username='user1', friend__username='user4')
        self.assertFriendEqual(friend,
                               Friend(pk=friend.pk, owner=self.user1, friend=user4, sent=0, received=0,
                                      deleted=False))
        self.assertFalse(Friend.objects.filter(owner__username='user4', friend__username='user1').exists())

        # Try to add a user that doesn't exist
        response = c.post('/v2/add_friend/', {'username': 'user_does_not_exist'},
                          HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)
        self.assertFalse(
            Friend.objects.filter(owner__username='user1', friend__username='user_does_not_exist').exists())

        response = c.post('/v2/add_friend/', HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)
        self.assertEqual(self.user1.friend_set.count(), 2)

    def test_get_friend_name(self):
        c = Client()
        response = c.get('/v2/get_name/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(response.data['data'], {'first_name': 'will', 'last_name': 'smith'})
        response = c.get('/v2/get_name/', HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)
        response = c.get('/v2/get_name/', {'not_username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)
        response = c.get('/v2/get_name/', {'username': 'user_does_not_exist'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)

    def test_delete_friend(self):
        c = Client()
        User.objects.create_user(username='user4', password='my_password4', first_name='will', last_name='smith')
        response = c.delete('/v2/delete_friend/', {'friend': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token2}',
                            content_type='application/json')
        self.assertContains(response, '', status_code=200)
        friend = Friend.objects.get(owner__username='user1', friend__username='user2', sent=2, received=0, deleted=True)

        # User 4 is not friends with us (or vice versa)
        response = c.delete('/v2/delete_friend/', {'friend': 'user4'}, HTTP_AUTHORIZATION=f'Token {self.token2}')
        self.assertContains(response, '', status_code=400)
        self.assertFalse(Friend.objects.filter(owner__username='user1', friend__username='user4').exists())

        # User does not exist
        response = c.delete('/v2/delete_friend/', {'friend': 'user_does_not_exist'},
                         HTTP_AUTHORIZATION=f'Token {self.token2}')
        self.assertContains(response, '', status_code=400)
        self.assertFalse(Friend.objects.filter(owner__username='user1',
                                               friend__username='user_does_not_exist').exists())

        friend.deleted = False
        response = c.get('/v2/delete_friend/', HTTP_AUTHORIZATION=f'Token {self.token2}')
        self.assertContains(response, '', status_code=400)
        Friend.objects.get(owner__username='user1', friend__username='user2', sent=2, received=0, deleted=False)

    def test_edit_user(self):
        c = Client()
        response = c.put('/v2/edit/', {'first_name': 'aaron'}, HTTP_AUTHORIZATION=f'Token {self.token1}',
                         content_type='application/json')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(User.objects.get(username='user1').first_name, 'aaron')
        self.assertEqual(User.objects.get(username='user1').last_name, '')

        response = c.put('/v2/edit/', {'last_name': 'adams'}, HTTP_AUTHORIZATION=f'Token {self.token1}',
                         content_type='application/json')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(User.objects.get(username='user1').first_name, 'aaron')
        self.assertEqual(User.objects.get(username='user1').last_name, 'adams')

        password = User.objects.get(username='user1').password
        response = c.put('/v2/edit/', {'password': 'password'}, HTTP_AUTHORIZATION=f'Token {self.token1}',
                         content_type='application/json')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(User.objects.get(username='user1').first_name, 'aaron')
        self.assertEqual(User.objects.get(username='user1').last_name, 'adams')
        self.assertNotEqual(User.objects.get(username='user1').password, password)
        self.assertNotEqual(User.objects.get(username='user1').password, 'password')
        self.token1 = Token.objects.create(user=self.user1)

        password = User.objects.get(username='user1').password
        response = c.put('/v2/edit/', {'last_name': 'last', 'first_name': 'first', 'password': 'new_pass'},
                         HTTP_AUTHORIZATION=f'Token {self.token1}',
                         content_type='application/json')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(User.objects.get(username='user1').first_name, 'first')
        self.assertEqual(User.objects.get(username='user1').last_name, 'last')
        self.assertNotEqual(User.objects.get(username='user1').password, password)
        self.assertNotEqual(User.objects.get(username='user1').password, 'new_pass')
        self.token1 = Token.objects.create(user=self.user1)

        response = c.put('/v2/edit/',
                         HTTP_AUTHORIZATION=f'Token {self.token1}',
                         content_type='application/json')
        self.assertContains(response, '', status_code=200)
        self.assertEqual(User.objects.get(username='user1').first_name, 'first')
        self.assertEqual(User.objects.get(username='user1').last_name, 'last')

    def test_send_alert(self):
        """
        Not totally sure how to test this
        Can do the basics, like improperly signed challenges (signed by a key other than the presented one,
        the challenge it says it signed isn't what was actually signed), the challenge signed doesn't exist in the
        database, challenges that aren't associated with the from id, to ids that aren't in the table,
        missing parameters, try weird characters/value in the message parameter (or in the other parameters)

        Try to send two requests simultaneously and see if anything breaks (verify the rows get locked)
        Try to send an alert that "should" work, check response is 200
        """
        c = Client()
        # These should work
        # self.validate_challenge(self.PUBLIC_KEY1)
        #
        # response = c.post('/v2/send_alert/', {'from': self.PUBLIC_KEY1, 'to': self.PUBLIC_KEY2, 'message': 'hi',
        #                                       'challenge': self.CHALLENGE, 'signature': self.PUBLIC_KEY1_SIG})
        # self.assertContains(response, '')
        # self.validate_challenge(self.PUBLIC_KEY1)
        # response = c.post('/v2/send_alert/', {'from': self.PUBLIC_KEY1, 'to': self.PUBLIC_KEY2, 'message': None,
        #                                       'challenge': self.CHALLENGE, 'signature': self.PUBLIC_KEY1_SIG})
        # self.assertContains(response, '')

        # This should fail because it doesn't expect GET requests
        response = c.get('/v2/send_alert/', {'to': 'user2', 'message': 'hi'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=405)
        response = c.post('/v2/send_alert/', {'message': 'hi'}, HTTP_AUTHORIZATION=f'Token {self.token1}')
        self.assertContains(response, '', status_code=400)

    def test_check_params_simple(self):
        """
        Just pass a bunch and check that the missing params line up, that it returns False each time something isn't
        right, returns True whenever all params are present
        Should also return True when more params than necessary passed
        """
        empty_dict = {}
        simple_dict = {
            "param1": "val1",
            "param2": "val2",
            "param3": "val3"
        }
        big_dict = {
            "to": "TO this person",
            "from": "FROM this person",
            "signature": "I've signed this",
            "challenge": "This is what I signed",
            "message": "This is what I want to say",
            "id": "This is an ID",
            "token": "This is a token"
        }

        list_empty = []
        list_params = ['param1', 'param2', 'param3']
        list_params_extra = ['param1', 'param2', 'param3', 'param4']
        list_params_fewer = ['param2', 'param3']

        list_values = ['signature', 'challenge', 'from', 'to', 'message', 'id', 'token']
        list_some_values = ['signature', 'from', 'to', 'message', 'challenge']

        # These should all succeed
        good, response = check_params(list_empty, empty_dict)
        self.assertTrue(good)
        good, response = check_params(list_params, simple_dict)
        self.assertTrue(good)
        good, response = check_params(list_params_fewer, simple_dict)
        self.assertTrue(good)
        good, response = check_params(list_values, big_dict)
        self.assertTrue(good)
        good, response = check_params(list_some_values, big_dict)
        self.assertTrue(good)

        # These should all fail
        good, response = check_params(list_params_extra, simple_dict)
        self.assertFalse(good)
        self.assertIn('param4', response.data['message'])
        self.assertEqual(response.status_code, 400)
        good, response = check_params(list_params, empty_dict)
        self.assertFalse(good)
        self.assertIn('param1', response.data['message'])
        self.assertIn('param2', response.data['message'])
        self.assertIn('param3', response.data['message'])
        self.assertEqual(response.status_code, 400)

    def test_check_params_weird(self):
        weird_dict = {
            "": "Empty key",
            "key1": 1,
            "key2": "Normal key-value",
            "key3": None,
            "key4": 3.14,
            "key5": {
                "key5_0": "",
                "key5_1": "another one?"
            },
            "key6": "",
            "key7": ["value1", "value2", 3, None, 3.14, ""]
        }

        list_keys = ['key1', '', 'key6', 'key7', 'key1', 'key2', 'key3', 'key4', 'key5']
        list_keys_extra = ['key1', '', 'key6', 'key7', 'key1', 'key2', 'key3', 'key4', 'key5', 'key5_0']

        good, response = check_params(list_keys, weird_dict)
        self.assertTrue(good)
        good, response = check_params(list_keys_extra, weird_dict)
        self.assertFalse(good)
        self.assertIn('key5_0', response.data['message'])
        self.assertEqual(response.status_code, 400)

    def test_private_functions_private(self):
        c = Client()
        response = c.get('/v2/verify_signature/')
        self.assertContains(response, '', status_code=404)
        response = c.get('/v2/check_params/')
        self.assertContains(response, '', status_code=404)
        response = c.get('/v2/build_response/')
        self.assertContains(response, '', status_code=404)
        response = c.get('/v2/string_response/')
        self.assertContains(response, '', status_code=404)
        response = c.get('/v2/verify_challenge/')
        self.assertContains(response, '', status_code=404)

    def test_auth_enforced(self):
        c = Client()
        for endpoint in auth_required_post_endpoints:
            response = c.post(f'/v2/{endpoint}/')
            self.assertContains(response, '', status_code=403)
            response = c.post(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token notavalidtoken')
            self.assertContains(response, '', status_code=403)

            response = c.get(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.put(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}',
                             content_type='application/json')
            self.assertContains(response, '', status_code=405)
            response = c.delete(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.patch(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)

        for endpoint in auth_required_get_endpoints:
            response = c.get(f'/v2/{endpoint}/')
            self.assertContains(response, '', status_code=401)
            response = c.get(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token notavalidtoken')
            self.assertContains(response, '', status_code=403)

            response = c.post(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.put(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}',
                             content_type='application/json')
            self.assertContains(response, '', status_code=405)
            response = c.delete(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.patch(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)

        for endpoint in auth_required_delete_endpoints:
            response = c.delete(f'/v2/{endpoint}/')
            self.assertContains(response, '', status_code=401)
            response = c.delete(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token notavalidtoken')
            self.assertContains(response, '', status_code=403)

            response = c.get(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.put(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}',
                             content_type='application/json')
            self.assertContains(response, '', status_code=405)
            response = c.post(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.patch(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)

        for endpoint in auth_required_put_endpoints:
            response = c.put(f'/v2/{endpoint}/', content_type='application/json')
            self.assertContains(response, '', status_code=401)
            response = c.put(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token notavalidtoken',
                             content_type='application/json')
            self.assertContains(response, '', status_code=403)

            response = c.get(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.post(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.delete(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)
            response = c.patch(f'/v2/{endpoint}/', HTTP_AUTHORIZATION=f'Token {self.token1}')
            self.assertContains(response, '', status_code=405)

    def test_api_integration(self):

        def get_tokens():
            for inner_user in users:
                inner_response = c.post(f'/v2/api_token_auth/', {'username': inner_user[0], 'password': inner_user[1]})
                self.assertContains(inner_response, '', status_code=200)
                inner_response_json = inner_response.data
                inner_user[4] = inner_response_json['token']

        c = Client()
        num_users: Final = 100

        # Stores the users that are available - each element should be [private key, challenge]
        users: list[list] = []
        # Generate some users
        for x in range(num_users):
            users.append([f'test_user_{x}', f'test_password_{x}', f'test_first_name_{x}', f'test_last_name_{x}', None])
            response = c.post('/v2/register_user/', {'username': users[x][0], 'password': users[x][1],
                                                     'first_name': users[x][2], 'last_name': users[x][3]})
            self.assertContains(response, '', status_code=200)

        # Get challenges for the users
        get_tokens()

        # Update the users with the new tokens
        for username, password, first_name, last_name, token in users:
            response = c.put('/v2/edit/', {'first_name': first_name + 'update'}, content_type='application/json',
                             HTTP_AUTHORIZATION=f'Token {token}')
            self.assertContains(response, '', status_code=200)

        # Check that it still works
        for username, password, first_name, last_name, token in users:
            response = c.get('/v2/get_info/', HTTP_AUTHORIZATION=f'Token {token}')
            self.assertContains(response, '', status_code=200)

        # Change passwords
        for x in range(len(users)):
            token = users[x][4]
            users[x][1] += 'updated'
            response = c.put('/v2/edit/', {'password': users[x][1]}, HTTP_AUTHORIZATION=f'Token {token}',
                             content_type='application/json')
            self.assertContains(response, '', status_code=200)

        # Token should no longer be valid
        for username, password, first_name, last_name, token in users:
            response = c.post('/v2/register_device/', {'fcm_token': 'fake_token'}, HTTP_AUTHORIZATION=f'Token {token}')
            self.assertContains(response, '', status_code=403)

        get_tokens()

        # Tokens should work now
        for username, password, first_name, last_name, token in users:
            response = c.post('/v2/add_friend/', {'username': random.choice(users)[0]},
                              HTTP_AUTHORIZATION=f'Token {token}')
            self.assertContains(response, '', status_code=200)

        for username, password, first_name, last_name, token in users:
            response = c.delete('/v2/delete_user_data/',
                                HTTP_AUTHORIZATION=f'Token {token}')
            self.assertContains(response, '', status_code=200)
            self.assertFalse(User.objects.filter(username=username).exists())
            self.assertFalse(Friend.objects.filter(owner__username=username).exists())
            self.assertFalse(Friend.objects.filter(friend__username=username).exists())
            self.assertFalse(Token.objects.filter(user__username=username).exists())

    def assertFriendEqual(self, expected: Friend, actual: Friend):
        self.assertEqual(expected.pk, actual.pk)
        self.assertEqual(expected.owner, actual.owner)
        self.assertEqual(expected.friend, actual.friend)
        self.assertEqual(expected.sent, actual.sent)
        self.assertEqual(expected.received, actual.received)
        self.assertEqual(expected.deleted, actual.deleted)
