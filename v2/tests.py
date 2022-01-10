import json

from typing import Final

from django.test import TestCase

# Create your tests here.
from v2.models import User, Challenge
from v2.views import check_params
from django.test import Client


class APIV2TestSuite(TestCase):
    PUBLIC_KEY1: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8VT4Fdb2TQm6OVu8wsasA65XQwnzv2jaVMn8+iGhgLlckf0vAh' \
                         '/xB6CCDhyawE9TCDlC66QfgpHW5Ld1CAw5w=='
    PUBLIC_KEY2: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuv6zaydP6LRu+VDl8ihLTWrYe2F0AEIoTWAeIvOjIdi' \
                         '8N1v+QxCYpyByP3NuA3YylwFrcQTfMQwqtzWUuo8dMg=='
    PUBLIC_KEY3: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgEOLhzzqZPP7ngKbWUv5FJ8HxcTIRrZqqddanCaKQ/3t7ZExB/wVsdr' \
                         'u5BuHinrRwInKVz7ni1ZfyUdp9tlitg=='
    PUBLIC_KEY4: Final = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC/GfZFNiVGCD0OGqclZc2+0k7Jdq16U3YMRqXjJ7GpJAMyy/2P9qdQA' \
                         'NOxDXdPFsltLUJbHEJ4WrfbPFTzqIDg=='

    CHALLENGE: Final = 'c~2:sdnzROtT[-Wi'

    PUBLIC_KEY1_SIG: Final = 'MEUCIQDSH24rAyrRDy2R5XeBuxiHW7JIUgkOBn+jo9Bj33gTfgIgCctBjgiA3qMB/f9BqouwrrFQoyjbDbGZmG' \
                             'mNq7jbVCM='
    PUBLIC_KEY2_SIG: Final = 'MEUCIC5CuJ8JBuNoL7q3qox/P8wLoC+zWKGIEqjlqq6Cr31YAiEAz1O+IoK84cpbsZf0zZW3Ahvmesb1jQUYBE' \
                             'OgscW/lkk='
    PUBLIC_KEY3_SIG: Final = 'MEUCIQC6vqSZHNp7dZOkNX6Jojs+HiMqpQe+QiN0mUWOBRWZbQIgNKiI/CP0n9SHKvAHQSLMobqmDRQEFhoxPw' \
                             'LO9pg9mWY='
    PUBLIC_KEY4_SIG: Final = 'MEYCIQDdkVimWDHzfupbXFomraAtpjFOJL5bI+5zUCdmFOWF8AIhALI3JOOLGmhVNvTZzztv6HKZ8Xr0O27A8F' \
                             'j1v4SD60d3'

    def setUp(self):
        User.objects.create(public_key=self.PUBLIC_KEY1, fcm_id='Fake')
        User.objects.create(public_key=self.PUBLIC_KEY2, fmc_id='Fake')

    @staticmethod
    def validate_challenge(public_key: str):
        Challenge.objects.update_or_create(challenge=Challenge, id_id=public_key, valid=True)

    def test_add_user_simple(self):
        """
        This should test upload_public_key
        Use both POST and PUT
        Add a user, update it, make sure a new one wasn't created
        Check status codes
        """
        c = Client()
        self.assertEqual(len(User.objects), 2)
        response = c.post('/v2/post_id', {'id': self.PUBLIC_KEY3, 'token': 'Fake3'})
        self.assertContains(response, '')
        self.assertEqual(len(User.objects), 3)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Fake3')
        self.assertEqual(user1.fcm_id, 'Fake')
        self.assertEqual(user2.fcm_id, 'Fake')
        self.validate_challenge(self.PUBLIC_KEY3)
        response = c.put('/v2/post_id', {'id': self.PUBLIC_KEY3,
                                         'token': 'Updated3',
                                         'signature': self.PUBLIC_KEY3_SIG,
                                         'challenge': self.CHALLENGE})
        self.assertContains(response, '')
        self.assertEqual(len(User.objects), 3)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3')
        self.assertEqual(user1.fcm_id, 'Fake')
        self.assertEqual(user2.fcm_id, 'Fake')

        response = c.post('/v2/post_id', {'id': self.PUBLIC_KEY4, 'token': 'Fake4'})
        self.assertContains(response, '')
        self.assertEqual(len(User.objects), 4)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Fake3')
        self.assertEqual(user4.fcm_id, 'Fake4')
        self.assertEqual(user1.fcm_id, 'Fake')
        self.assertEqual(user2.fcm_id, 'Fake')
        self.validate_challenge(self.PUBLIC_KEY3)
        response = c.put('/v2/post_id', {'id': self.PUBLIC_KEY3,
                                         'token': 'Updated3.1',
                                         'signature': self.PUBLIC_KEY3_SIG,
                                         'challenge': self.CHALLENGE})
        self.assertContains(response, '')
        self.assertEqual(len(User.objects), 4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3.1')
        self.assertEqual(user4.fcm_id, 'Fake4')
        self.assertEqual(user1.fcm_id, 'Fake')
        self.assertEqual(user2.fcm_id, 'Fake')
        self.validate_challenge(self.PUBLIC_KEY4)
        response = c.put('/v2/post_id', {'id': self.PUBLIC_KEY4,
                                         'token': 'Updated4',
                                         'signature': self.PUBLIC_KEY4_SIG,
                                         'challenge': self.CHALLENGE})
        self.assertContains(response, '')
        self.assertEqual(len(User.objects), 4)
        user3 = User.objects.get(public_key=self.PUBLIC_KEY3)
        user4 = User.objects.get(public_key=self.PUBLIC_KEY4)
        user1 = User.objects.get(public_key=self.PUBLIC_KEY1)
        user2 = User.objects.get(public_key=self.PUBLIC_KEY2)
        self.assertEqual(user3.fcm_id, 'Updated3.1')
        self.assertEqual(user4.fcm_id, 'Updated4')
        self.assertEqual(user1.fcm_id, 'Fake')
        self.assertEqual(user2.fcm_id, 'Fake')

    def test_add_user_weird(self):
        """
        Test malformed requests (missing required parameters, too many parameters, etc.)
        """
        c = Client()
        response = c.post('/v2/post_id', {'id': self.PUBLIC_KEY3})
        self.assertContains(response, '', status_code=400)
        self.assertEqual(len(User.objects.filter(public_key=self.PUBLIC_KEY3)), 0)
        response = c.put('/v2/post_id', {'id': self.PUBLIC_KEY2, 'token': 'Updated2'})
        self.assertContains(response, '', status_code=400)
        self.assertEqual(User.objects.get(public_key=self.PUBLIC_KEY2).fcm_id, 'Fake')
        response = c.post('/v2/post_id')
        self.assertContains(response, '', status_code=400)

    def test_get_challenge_simple(self):
        """
        This should test get_challenge
        Request a challenge, make sure the one in the database is the same as the one returned
        Test with invalid public_keys (or missing parameters)
        Make sure no two challenges are the same
        Check status codes
        """
        c = Client()
        response = c.get(f'/v2/{self.PUBLIC_KEY1}')
        self.assertContains(response, 'true', status_code=200)
        challenge = Challenge.objects.get(id__public_key=self.PUBLIC_KEY1)
        self.assertContains(response, str(challenge.challenge))
        response1 = c.get(f'/v2/{self.PUBLIC_KEY1}')
        response1_decoded = json.loads(response1.body)
        response_decoded = json.loads(response.body)
        self.assertNotEqual(response_decoded['data'], response1_decoded['data'])
        self.assertEqual(len(Challenge.objects.filter(id__public_key=self.PUBLIC_KEY1)), 2)

        response = c.get(f'/v2/{self.PUBLIC_KEY2}')
        self.assertContains(response, 'true', status_code=200)
        challenge = Challenge.objects.get(id__public_key=self.PUBLIC_KEY2)
        self.assertContains(response, str(challenge.challenge))
        response_decoded = json.loads(response.body)
        self.assertEqual(challenge.challenge, response_decoded['data'])
        c.get(f'/v2/{self.PUBLIC_KEY2}')
        self.assertEqual(len(Challenge.objects.filter(id_id=self.PUBLIC_KEY1)), 2)
        self.assertEqual(len(Challenge.objects.filter(id_id=self.PUBLIC_KEY2)), 2)

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
        pass

    def test_verify_challenge(self):
        """
        Make sure a challenge not in the database (but otherwise valid) fails
        Make sure a challenge in the database but set to a different user fails
        Make sure after a challenge is used it isn't valid again
        """
        pass

    def test_verify_signature(self):
        """
        Improperly signed challenges (signed by a key other than the presented one,
        the challenge it says it signed isn't what was actually signed) should return False
        Correctly signed challenges should return True
        """
        pass

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
        self.assertContains(response, 'param4', status_code=400)
        good, response = check_params(list_params, empty_dict)
        self.assertFalse(good)
        self.assertContains(response, 'param1', status_code=400)
        self.assertContains(response, 'param2', status_code=400)
        self.assertContains(response, 'param3', status_code=400)

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
        self.assertContains(response, 'key5_0', status_code=400)
