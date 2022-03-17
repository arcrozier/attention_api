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

from v2.models import User, Challenge
from v2.views import check_params, verify_signature, verify_challenge


# Create your tests here.


class APIV2TestSuite(TestCase):
    PUBLIC_KEY1: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdgrPmjIaYmYfbKfEKlFGZVo_gaPJH855GqAKCKZblvCxqqjjSscACXh' \
                         'biNshfKzvZUQxXmPH6FcbKOsHPcWOpQ== '
    PUBLIC_KEY2: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqbqVxkXQcAYbr-dQLUX1QystJaEql_W9N6ZwGBr5wpo_vAtYvgGq2hW' \
                         'Tewlp-9Ym7pBEDCMLGvFu-6EgYuntRg=='
    PUBLIC_KEY3: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcLIU2jdMTsW_tkmq_DdAjFd1pZx760aikBA_RQE9WrXJgKIRovgg_H2' \
                         'TvIKBmugeUYUlS8yc95Kgvb6C_u1EqQ=='
    PUBLIC_KEY4: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbQriMnfHzQWgawpGNNS1hthbfakhBK21h2dRrS_msOIpTKqlBExc55K' \
                         'm9U6t0zHOuBl_L2KCMr2kVr-FMK4h4A=='

    CHALLENGE: Final = 1

    PUBLIC_KEY1_SIG: Final = 'MEUCIQDLU+01TwU5SN0OkUOEv6ax5VefCHC7GmhhpDSpd7t0uAIgGUy02/QHoTYEoRRPtPRq3BdZ1n+KmRaoZDf' \
                             'sfOP7v+E='
    PUBLIC_KEY2_SIG: Final = 'MEUCIQDoRSmq8ppt3/YEJe65AWOVA04BozXXA24LKVcpoZTkwwIgL2SQRE+QmxKUoE7fyjkNu3RlkHa1vF62BoW' \
                             'TkSi0w7E='
    PUBLIC_KEY3_SIG: Final = 'MEYCIQDgZOi3GyV9Vcd7lKeppedopo1aOcyp/UKFWEQ9cZJGvQIhAP8BXXxxyLqUg9ytihmThav+blchihwR471' \
                             'SDAo/+AA8'
    PUBLIC_KEY4_SIG: Final = 'MEUCIQCjoweh1a6c4jPTobZofwVQIQm+SInYlud8qOayBxhoGAIgBmbc1M9P/ja96LaQshrtoZu0QA/fDAbFe55' \
                             'R0zuefOM='

    def setUp(self):
        User.objects.create(public_key=self.PUBLIC_KEY1, fcm_id='Fake1')
        User.objects.create(public_key=self.PUBLIC_KEY2, fcm_id='Fake2')

    @staticmethod
    def validate_challenge(public_key: str):
        Challenge.objects.update_or_create(challenge=APIV2TestSuite.CHALLENGE,
                                           defaults={'id_id': public_key, 'valid': True})

    def test_add_user_simple(self):
        """
        This should test upload_public_key
        Use both POST and PUT
        Add a user, update it, make sure a new one wasn't created
        Check status codes
        """
        c = Client()
        self.assertEqual(User.objects.count(), 2)
        response = c.post('/v2/post_id/', {'id': self.PUBLIC_KEY3, 'token': 'Fake3'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 3)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Fake3')
        self.assertEqual(user1.fcm_id, 'Fake1')
        self.assertEqual(user2.fcm_id, 'Fake2')
        self.validate_challenge(self.PUBLIC_KEY3)
        response = c.put('/v2/post_id/', {'id': self.PUBLIC_KEY3,
                                          'token': 'Updated3',
                                          'signature': self.PUBLIC_KEY3_SIG,
                                          'challenge': self.CHALLENGE}, content_type='application/json')
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 3)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3')
        self.assertEqual(user1.fcm_id, 'Fake1')
        self.assertEqual(user2.fcm_id, 'Fake2')

        response = c.post('/v2/post_id/', {'id': self.PUBLIC_KEY4, 'token': 'Fake4'})
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 4)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3')
        self.assertEqual(user4.fcm_id, 'Fake4')
        self.assertEqual(user1.fcm_id, 'Fake1')
        self.assertEqual(user2.fcm_id, 'Fake2')
        self.validate_challenge(self.PUBLIC_KEY3)
        response = c.put('/v2/post_id/', {'id': self.PUBLIC_KEY3,
                                          'token': 'Updated3.1',
                                          'signature': self.PUBLIC_KEY3_SIG,
                                          'challenge': self.CHALLENGE}, content_type='application/json')
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3.1')
        self.assertEqual(user4.fcm_id, 'Fake4')
        self.assertEqual(user1.fcm_id, 'Fake1')
        self.assertEqual(user2.fcm_id, 'Fake2')
        self.validate_challenge(self.PUBLIC_KEY4)
        response = c.put('/v2/post_id/', {'id': self.PUBLIC_KEY4,
                                          'token': 'Updated4',
                                          'signature': self.PUBLIC_KEY4_SIG,
                                          'challenge': self.CHALLENGE}, content_type='application/json')
        self.assertContains(response, '')
        self.assertEqual(User.objects.count(), 4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3.1')
        self.assertEqual(user4.fcm_id, 'Updated4')
        self.assertEqual(user1.fcm_id, 'Fake1')
        self.assertEqual(user2.fcm_id, 'Fake2')

    def test_add_user_weird(self):
        """
        Test malformed requests (missing required parameters, too many parameters, etc.)
        """
        c = Client()
        response = c.post('/v2/post_id/', {'id': self.PUBLIC_KEY3})
        self.assertContains(response, '', status_code=400)
        self.assertEqual(User.objects.filter(public_key=self.PUBLIC_KEY3).count(), 0)
        response = c.put('/v2/post_id/', {'id': self.PUBLIC_KEY2, 'token': 'Updated2'}, content_type='application/json')
        self.assertContains(response, '', status_code=403)
        self.assertEqual(User.objects.get(public_key=self.PUBLIC_KEY2).fcm_id, 'Fake2')
        response = c.post('/v2/post_id/')
        self.assertContains(response, '', status_code=400)
        response = c.get('v2/post_id/', {'id': self.PUBLIC_KEY4, 'token': 'Updated2'})
        self.assertContains(response, '', status_code=404)

    def test_get_challenge_simple(self):
        """
        This should test get_challenge
        Request a challenge, make sure the one in the database is the same as the one returned
        Test with invalid public_keys (or missing parameters)
        Make sure no two challenges are the same
        Check status codes
        """
        c = Client()
        response = c.get(f'/v2/get_challenge/{self.PUBLIC_KEY1}/')
        self.assertContains(response, 'true', status_code=200)
        challenge = Challenge.objects.get(id__public_key=self.PUBLIC_KEY1)
        self.assertContains(response, str(challenge.challenge))
        response1 = c.get(f'/v2/get_challenge/{self.PUBLIC_KEY1}/')
        response1_decoded = response1.data
        response_decoded = response.data
        self.assertNotEqual(response_decoded['data'], response1_decoded['data'])
        self.assertEqual(Challenge.objects.filter(id__public_key=self.PUBLIC_KEY1).count(), 2)

        response = c.get(f'/v2/get_challenge/{self.PUBLIC_KEY2}/')
        self.assertContains(response, 'true', status_code=200)
        challenge = Challenge.objects.get(id__public_key=self.PUBLIC_KEY2)
        self.assertContains(response, str(challenge.challenge))
        response_decoded = response.data
        self.assertEqual(str(challenge.challenge), response_decoded['data'])
        c.get(f'/v2/get_challenge/{self.PUBLIC_KEY2}/')
        self.assertEqual(Challenge.objects.filter(id_id=self.PUBLIC_KEY1).count(), 2)
        self.assertEqual(Challenge.objects.filter(id_id=self.PUBLIC_KEY2).count(), 2)

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
        self.validate_challenge(self.PUBLIC_KEY1)
        response = c.get('/v2/send_alert/', {'from': self.PUBLIC_KEY1, 'to': self.PUBLIC_KEY2, 'message': 'hi',
                                             'challenge': self.CHALLENGE, 'signature': self.PUBLIC_KEY1_SIG})
        self.assertContains(response, '', status_code=405)

    def test_verify_challenge(self):
        # Make sure after a challenge is used it isn't valid again
        self.validate_challenge(self.PUBLIC_KEY1)
        verify_challenge(str(self.CHALLENGE), self.PUBLIC_KEY1, self.PUBLIC_KEY1_SIG)
        self.assertRaises(ObjectDoesNotExist, verify_challenge, str(self.CHALLENGE), self.PUBLIC_KEY1,
                          self.PUBLIC_KEY1_SIG)

        # Make sure a challenge in the database but set to a different user fails
        self.validate_challenge(self.PUBLIC_KEY2)
        self.assertRaises(ObjectDoesNotExist, verify_challenge, str(self.CHALLENGE), self.PUBLIC_KEY1,
                          self.PUBLIC_KEY1_SIG)
        self.assertRaises(ObjectDoesNotExist, verify_challenge, str(self.CHALLENGE), self.PUBLIC_KEY3,
                          self.PUBLIC_KEY3_SIG)

        # Make sure a challenge not in the database (but otherwise valid) fails
        Challenge.objects.get(challenge=self.CHALLENGE).delete()
        self.assertRaises(ObjectDoesNotExist, verify_challenge, str(self.CHALLENGE), self.PUBLIC_KEY1,
                          self.PUBLIC_KEY1_SIG)

    def test_verify_signature(self):
        """
        Improperly signed challenges (signed by a key other than the presented one,
        the challenge it says it signed isn't what was actually signed) should return False
        Correctly signed challenges should return True
        """
        self.assertRaises(InvalidSignature, verify_signature, str(self.CHALLENGE), self.PUBLIC_KEY1_SIG,
                          self.PUBLIC_KEY2)
        # The signature was signed by the provided public key, but it signed "2" not "1"
        self.assertRaises(InvalidSignature, verify_signature, str(self.CHALLENGE),
                          'MEQCIAhi3nD7gPjxIkmzSa+xo8tln6+m0uW5I8IY+z5/gyWMAiBo'
                          'npMP0lghf1oMlh2qEMRN9gGV6I5XEq2seFApVrDLhQ==',
                          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcD3KRwFeDtHAQ69k'
                          'Sz9/oeqdjfmH2pDHMLa54x1wQFKJ15gGl5LjBiiNyinyx59993jRh'
                          'FG4ZEfFEL/iIjaMiw==')
        verify_signature(str(self.CHALLENGE), self.PUBLIC_KEY3_SIG, self.PUBLIC_KEY3)

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
