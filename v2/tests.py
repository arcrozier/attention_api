import base64
import json
import random
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.exceptions import ObjectDoesNotExist
from django.test import Client
from django.test import TestCase

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from v2.models import FCMTokens, Friend
from v2.views import check_params


# Create your tests here.
# TODO check that unauthenticated requests are denied


class APIV2TestSuite(TestCase):

    def setUp(self):
        User.objects.create_user(username='user1', password='my_password')
        User.objects.create_user(username='user2', password='my_password2', first_name='will', last_name='smith')
        self.token = Token.objects.create(user='user1')

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

        response = c.post('/v2/register_user/', {'username': 'user4', 'password': 'my_password4', 'first_name':
            'john', 'last_name': 'dohn'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 4)
        user1 = User.objects.get(username='user1')
        user2 = User.objects.get(username='user2')
        user3 = User.objects.get(username='user3')
        user4 = User.objects.get(username='user4')

    def test_register_device(self):
        c = Client()
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'})
        self.assertContains(response, '', 401)
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        self.assertContains(response, '', 200)
        self.assertEqual(FCMTokens.objects.get(username='user1'), 'fake_token')
        response = c.post('/v2/register_device/', {'fcm_token': 'fake token'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        self.assertContains(response, '', 400)
        self.assertEqual(FCMTokens.objects.get(username='user1'), 'fake token')

    def test_add_friend(self):
        # Test undeleting a friend doesn't reset sent/received fields
        c = Client()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        self.assertContains(response, '', 200)
        friend: Friend = Friend.objects.get(owner_id='user1', friend_id='user2')
        self.assertEqual(friend,
                         Friend(owner_id='user1', friend_id='user2', sent=0, received=0, deleted=False))
        friend.sent = 1
        friend.received = 2
        friend.save()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        friend = Friend.objects.get(owner_id='user1', friend_id='user2')
        self.assertEqual(friend,
                         Friend(owner_id='user1', friend_id='user2', sent=1, received=2, deleted=False))
        friend.deleted = True
        friend.save()
        response = c.post('/v2/add_friend/', {'username': 'user2'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        friend = Friend.objects.get(owner_id='user1', friend_id='user2')
        self.assertEqual(friend,
                         Friend(owner_id='user1', friend_id='user2', sent=1, received=2, deleted=False))

    def test_add_user_weird(self):
        """
        Test malformed requests (missing required parameters, too many parameters, etc.)
        """
        c = Client()
        response = c.post('/v2/register_user/', {'username': 'user2', 'password': 'my_password3', 'first_name':
            'joe', 'last_name': 'blow'})
        self.assertContains(response, '', status_code=400)
        self.assertEqual(User.objects.get(username='user2').first_name, 'will')
        self.assertEqual(User.objects.get(username='user2').last_name, 'smith')
        response = c.put('/v2/register_user/', {'id': 'user1', 'token': 'Updated2'},
                         content_type='application/json')
        self.assertContains(response, '', status_code=404)
        response = c.post('/v2/register_user/')
        self.assertContains(response, '', status_code=400)
        response = c.get('v2/register_user/', {'username': 'user3', 'password': 'my_password3', 'first_name':
            'joe', 'last_name': 'blow'})
        self.assertContains(response, '', status_code=404)

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
        response = c.get('/v2/send_alert/', {'to': 'user2', 'message': 'hi'}, HTTP_AUTHORIZATION=f'Token {self.token}')
        self.assertContains(response, '', status_code=405)

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

    def test_api_integration(self):

        def sign(inner_challenge: str, inner_private_key):
            # key = serialization.load_der_private_key(base64.b64decode(inner_private_key), password=None)
            return base64.urlsafe_b64encode(inner_private_key.sign(inner_challenge.encode(), ec.ECDSA(hashes.SHA256(

            )))).decode()

        def test_alerts(status: int):
            for inner_private_key, inner_challenge in users:
                inner_response = c.post('/v2/send_alert/', {'to': base64_public_key(random.choice(users)[0]),
                                                            'from': base64_public_key(inner_private_key),
                                                            'message': random.choice(('HI!! ', '')),
                                                            'signature': sign(inner_challenge, inner_private_key),
                                                            'challenge': inner_challenge})
                self.assertContains(inner_response, '', status_code=status)

        def get_challenges():
            for inner_user in users:
                inner_response = c.get(f'/v2/get_challenge/{base64_public_key(inner_user[0])}/')
                self.assertContains(inner_response, '', status_code=200)
                inner_response_json = inner_response.data
                inner_user[1] = inner_response_json['data']

        def base64_public_key(inner_private_key):
            return base64.urlsafe_b64encode(inner_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode()

        c = Client()
        num_users: Final = 100

        # Stores the users that are available - each element should be [private key, challenge]
        users: list[list] = []
        # Generate some users
        for x in range(num_users):
            private_key = ec.generate_private_key(ec.SECP256R1())
            assert [private_key, None] not in users
            users.append([private_key, None])
            response = c.post('/v2/post_id/', {'id': base64_public_key(users[x][0]), 'token': f'fake{x}'})
            self.assertContains(response, '', status_code=200)

        # Get challenges for the users
        get_challenges()

        # Send alerts from those users
        # test_alerts(200)

        # Try to update the users with the same challenges (all should fail)
        for private_key, _ in users:
            public_key = base64_public_key(private_key)
            response = c.post('/v2/post_id/', {'id': public_key, 'token': f'fake{public_key}'})
            self.assertContains(response, '', status_code=403)

        # Get new challenges
        get_challenges()

        # Update the users with the new challenges
        for private_key, challenge in users:
            public_key = base64_public_key(private_key)
            response = c.post('/v2/post_id/', {'id': public_key, 'token': f'fake{public_key}',
                                               'challenge': challenge, 'signature': sign(challenge, private_key)})
            self.assertContains(response, '', status_code=200)

        # Send alerts
        test_alerts(403)

        # Get new challenges
        get_challenges()

        # Send alerts
        # test_alerts(200)

        for x in range(2):
            # Try mismatching public keys and challenges
            for y in range(num_users):
                challenge_row = random.randint(0, num_users - 1)
                if y == challenge_row:
                    continue
                response = c.post('/v2/send_alert/', {'to': base64_public_key(random.choice(users)[0]),
                                                      'from': base64_public_key(users[y][0]),
                                                      'message': random.choice(('HI!! ', '')),
                                                      'signature': sign(users[challenge_row][1], users[y][0]),
                                                      'challenge': users[challenge_row][1]})
                self.assertContains(response, '', status_code=403)

            # Get new challenges
            get_challenges()

        # Try mixed up parameters
        for private_key, challenge in users:
            response = c.post('/v2/send_alert/', {'to': base64_public_key(random.choice(users)[0]),
                                                  'from': base64_public_key(private_key),
                                                  'message': random.choice(('HI!! ', '')),
                                                  'signature': challenge,
                                                  'challenge': sign(challenge, private_key)})
            self.assertContains(response, '', status_code=403)

        # Get new challenges
        get_challenges()

        # Try impersonating another user
        for private_key, challenge in users:
            private_from = random.choice(users)[0]
            random_to = base64_public_key(random.choice(users)[0])
            random_from = base64_public_key(private_from)
            if random_from == random_to or private_from == private_key:
                continue
            response = c.post('/v2/send_alert/', {'to': random_to,
                                                  'from': random_from,
                                                  'message': random.choice(('HI!! ', '')),
                                                  'signature': sign(challenge, private_key),
                                                  'challenge': challenge})
            self.assertContains(response, '', status_code=403)

        # Try missing parameters
        for private_key, challenge in users:
            sample_dict = {'to': base64_public_key(random.choice(users)[0]),
                           'from': base64_public_key(private_key),
                           'message': random.choice(('HI!! ', '')),
                           'signature': sign(challenge, private_key),
                           'challenge': challenge}
            selected_keys = random.sample(list(sample_dict), random.randint(0, len(sample_dict) - 1))
            selected_params = {key: sample_dict[key] for key in selected_keys}
            response = c.post('/v2/send_alert/', selected_params)
            self.assertContains(response, '', status_code=400)
