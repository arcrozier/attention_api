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

    def setUp(self):
        User.objects.create(public_key=self.PUBLIC_KEY1, fcm_id='Fake')
        User.objects.create(public_key=self.PUBLIC_KEY2, fmc_id='Fake')

    def test_add_user_simple(self):
        """
        This should test upload_public_key
        Use both POST and PUT
        Add a user, update it, make sure a new one wasn't created
        Test malformed requests (missing required parameters, too many parameters, etc.)
        Check status codes
        """
        pass

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
        self.assertEqual(len(Challenge.objects.filter(id__public_key=self.PUBLIC_KEY1)), 2)
        self.assertEqual(len(Challenge.objects.filter(id__public_key=self.PUBLIC_KEY2)), 2)

    def test_send_alert(self):
        """
        Not totally sure how to test this
        Can do the basics, like improperly signed challenges (signed by a key other than the presented one,
        the challenge it says it signed isn't what was actually signed), the challenge signed doesn't exist in the
        database, challenges that aren't associated with the from id, to ids that aren't in the table,
        missing parameters, try weird characters/value in the message parameter (or in the other parameters)

        Make sure after a challenge is used it isn't valid again
        Try to send two requests simultaneously and see if anything breaks (verify the rows get locked)
        Try to send an alert that "should" work, check response is 200
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
