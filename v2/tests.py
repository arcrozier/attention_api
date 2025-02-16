import base64
import io
import random
from typing import Final

from PIL import Image
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client
from django.test import TestCase
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from v2.models import FCMTokens, Friend, Photo
from v2.utils import check_params

# Create your tests here.

auth_required_post_endpoints = [
    "send_alert",
    "register_device",
    "add_friend",
    "alert_read",
    "alert_delivered",
    "block_user",
    "ignore_user",
    "report",
]
auth_required_get_endpoints = ["get_name", "get_info"]
auth_required_delete_endpoints = ["delete_friend/friend", "delete_user_data"]
auth_required_put_endpoints = ["edit", "edit_friend_name"]

TEST_PHOTO_DIR: Final = settings.BASE_DIR / "v2" / "test_photos"


class APIV2TestSuite(TestCase):

    def setUp(self):
        self.user1 = get_user_model().objects.create_user(
            username="user1",
            password="my_password",
            first_name="poppin",
            last_name="pippin",
        )
        self.user2 = get_user_model().objects.create_user(
            username="user2",
            password="my_password2",
            first_name="will",
            last_name="smith",
            email="test@sample.verify",
        )
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
        self.assertEqual(get_user_model().objects.count(), 2)
        response = c.post(
            "/v2/register_user/",
            {
                "username": "user3",
                "password": "my_password3",
                "first_name": "joe",
                "last_name": "blow",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        self.assertContains(response, "")
        self.assertEqual(get_user_model().objects.count(), 3)
        user1 = get_user_model().objects.get(username="user1")
        user2 = get_user_model().objects.get(username="user2")
        user3 = get_user_model().objects.get(username="user3")
        self.assertEqual(user1.first_name, "poppin")
        self.assertEqual(user1.last_name, "pippin")
        self.assertEqual(user1.email, None)
        self.assertEqual(user2.first_name, "will")
        self.assertEqual(user2.last_name, "smith")
        self.assertEqual(user2.email, "test@sample.verify")
        self.assertEqual(user3.first_name, "joe")
        self.assertEqual(user3.last_name, "blow")
        self.assertEqual(user3.email, None)

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user4",
                "password": "my_password4",
                "first_name": "john",
                "last_name": "dohn",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        self.assertContains(response, "")
        self.assertEqual(get_user_model().objects.count(), 4)
        user1 = get_user_model().objects.get(username="user1")
        user2 = get_user_model().objects.get(username="user2")
        user3 = get_user_model().objects.get(username="user3")
        user4 = get_user_model().objects.get(username="user4")
        self.assertEqual(user1.first_name, "poppin")
        self.assertEqual(user1.last_name, "pippin")
        self.assertEqual(user1.email, None)
        self.assertEqual(user2.first_name, "will")
        self.assertEqual(user2.last_name, "smith")
        self.assertEqual(user2.email, "test@sample.verify")
        self.assertEqual(user3.first_name, "joe")
        self.assertEqual(user3.last_name, "blow")
        self.assertEqual(user3.email, None)
        self.assertEqual(user4.first_name, "john")
        self.assertEqual(user4.last_name, "dohn")
        self.assertEqual(user4.email, None)

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "valid_email@example.com",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        self.assertContains(response, "")
        self.assertEqual(get_user_model().objects.count(), 5)
        user1 = get_user_model().objects.get(username="user1")
        user2 = get_user_model().objects.get(username="user2")
        user3 = get_user_model().objects.get(username="user3")
        user4 = get_user_model().objects.get(username="user4")
        user5 = get_user_model().objects.get(username="user5")
        self.assertEqual(user1.first_name, "poppin")
        self.assertEqual(user1.last_name, "pippin")
        self.assertEqual(user1.email, None)
        self.assertEqual(user2.first_name, "will")
        self.assertEqual(user2.last_name, "smith")
        self.assertEqual(user2.email, "test@sample.verify")
        self.assertEqual(user3.first_name, "joe")
        self.assertEqual(user3.last_name, "blow")
        self.assertEqual(user3.email, None)
        self.assertEqual(user4.first_name, "john")
        self.assertEqual(user4.last_name, "dohn")
        self.assertEqual(user4.email, None)
        self.assertEqual(user5.first_name, "sean")
        self.assertEqual(user5.last_name, "bean")
        self.assertEqual(user5.email, "valid_email@example.com")

    def test_add_user_weird(self):
        """
        Test malformed requests (missing required parameters, too many parameters, etc.)
        """
        c = Client()
        response = c.post(
            "/v2/register_user/",
            {
                "username": "user2",
                "password": "my_password3",
                "first_name": "joe",
                "last_name": "blow",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        print(response.data)
        self.assertContains(response, "", status_code=400)
        self.assertEqual(
            get_user_model().objects.get(username="user2").first_name, "will"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user2").last_name, "smith"
        )

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user3",
                "password": "my_password3",
                "first_name": "joe",
                "last_name": "blow",
                "email": "invalid_email",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        print(response.data)
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user3").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user3",
                "password": "my_password3",
                "first_name": "joe",
                "last_name": "blow",
                "email": "invalid_email@gmail",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        print(response.data)
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user3").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user3",
                "first_name": "joe",
                "last_name": "blow",
                "email": "valid_email@gmail.com",
                "tos_agree": "yes",
            },
            content_type=get_content_type(),
        )
        print(response.data)
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user3").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user3",
                "first_name": "joe",
                "last_name": "blow",
                "password": "6chars",
                "email": "valid_email@gmail.com",
                "tos_agree": "yes",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user3").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "invalid] 😃user",
                "first_name": "joe",
                "last_name": "blow",
                "password": "good_password",
                "email": "valid_email@gmail.com",
                "tos_agree": "yes",
            },
        )
        print(response.data)
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            get_user_model().objects.filter(username="invalid] 😃user").exists()
        )

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "valid_email@example.com",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user5").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "valid_email@example.com",
                "tos_agree": "Yes",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user5").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "valid_email@example.com",
                "tos_agree": "no",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user5").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "valid_email@example.com",
                "tos_agree": "",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user5").exists())

        response = c.post(
            "/v2/register_user/",
            {
                "username": "user5",
                "password": "my_password5",
                "first_name": "sean",
                "last_name": "bean",
                "email": "test@sample.verify",
                "tos_agree": "yes",
            },
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(get_user_model().objects.filter(username="user5").exists())

        response = c.put(
            "/v2/register_user/",
            {"id": "user1", "token": "Updated2"},
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=405)
        response = c.post("/v2/register_user/")
        self.assertContains(response, "", status_code=400)
        response = c.get(
            "/v2/register_user/",
            {
                "username": "user3",
                "password": "my_password3",
                "first_name": "joe",
                "last_name": "blow",
            },
        )
        self.assertContains(response, "", status_code=405)

    def test_register_device(self):
        c = Client()
        response = c.post("/v2/register_device/", {"fcm_token": "fake token"})
        self.assertContains(response, "", status_code=403)
        response = c.post(
            "/v2/register_device/",
            {"fcm_token": "fake token"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            FCMTokens.objects.get(user__username="user1").fcm_token, "fake token"
        )
        response = c.post(
            "/v2/register_device/",
            {"fcm_token": "fake token"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertEqual(
            FCMTokens.objects.get(user__username="user1").fcm_token, "fake token"
        )

    def test_unregister_device(self):
        c = Client()
        FCMTokens.objects.create(user=self.user1, fcm_token="fake token")
        FCMTokens.objects.create(user=self.user1, fcm_token="fake token 1")
        FCMTokens.objects.create(user=self.user2, fcm_token="fake token 2")
        response = c.post(
            "/v2/unregister_device/",
            {"fcm_token": "fake token"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type=get_content_type(),
        )
        self.assertContains(response, "", status_code=200)
        self.assertFalse(
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token").exists()
        )
        self.assertEqual(
            1,
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token 1").count(),
        )
        self.assertEqual(
            1,
            FCMTokens.objects.filter(user=self.user2, fcm_token="fake token 2").count(),
        )

        response = c.post(
            "/v2/unregister_device/",
            {"fcm_token": "fake token 2"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type=get_content_type(),
        )
        self.assertContains(response, "", status_code=200)
        self.assertFalse(
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token").exists()
        )
        self.assertEqual(
            1,
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token 1").count(),
        )
        self.assertFalse(
            FCMTokens.objects.filter(user=self.user2, fcm_token="fake token 2").exists()
        )

        response = c.post(
            "/v2/unregister_device/",
            {"fcm_token": "fake token"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type=get_content_type(),
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token").exists()
        )
        self.assertEqual(
            1,
            FCMTokens.objects.filter(user=self.user1, fcm_token="fake token 1").count(),
        )
        self.assertFalse(
            FCMTokens.objects.filter(user=self.user2, fcm_token="fake token 2").exists()
        )

    def test_add_friend(self):
        # Test undeleting a friend doesn't reset sent/received fields
        c = Client()
        response = c.post(
            "/v2/add_friend/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type=get_content_type(),
        )
        print(response.data)
        self.assertContains(response, "", status_code=200)
        friend: Friend = Friend.objects.get(
            owner__username="user1", friend__username="user2"
        )
        self.assertFriendEqual(
            friend,
            Friend(
                pk=friend.pk,
                owner=self.user1,
                friend=self.user2,
                sent=0,
                received=0,
                deleted=False,
            ),
        )
        friend.sent = 1
        friend.received = 2
        friend.save()
        response = c.post(
            "/v2/add_friend/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type=get_content_type(),
        )
        self.assertContains(response, "", status_code=200)
        friend = Friend.objects.get(owner__username="user1", friend__username="user2")
        self.assertFriendEqual(
            friend,
            Friend(
                pk=friend.pk,
                owner=self.user1,
                friend=self.user2,
                sent=1,
                received=2,
                deleted=False,
            ),
        )
        friend.deleted = True
        friend.save()
        response = c.post(
            "/v2/add_friend/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        friend = Friend.objects.get(owner__username="user1", friend__username="user2")
        self.assertFriendEqual(
            friend,
            Friend(
                pk=friend.pk,
                owner=self.user1,
                friend=self.user2,
                sent=1,
                received=2,
                deleted=False,
            ),
        )

        # Check that user1 adding user4 as a friend does not add user1 as a friend of user4
        # i.e. user1 -> user4, but user4 !-> user1
        user4 = get_user_model().objects.create_user(
            username="user4",
            password="my_password4",
            first_name="will",
            last_name="skill",
        )

        Photo.objects.create(user=user4, photo="test")
        response = c.post(
            "/v2/add_friend/",
            {"username": "user4"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        friend: Friend = Friend.objects.get(
            owner__username="user1", friend__username="user4"
        )
        self.assertFriendEqual(
            friend,
            Friend(
                pk=friend.pk,
                owner=self.user1,
                friend=user4,
                sent=0,
                received=0,
                deleted=False,
            ),
        )
        self.assertFalse(
            Friend.objects.filter(
                owner__username="user4", friend__username="user1"
            ).exists()
        )

        # Try to add a user that doesn't exist
        response = c.post(
            "/v2/add_friend/",
            {"username": "user_does_not_exist"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.filter(
                owner__username="user1", friend__username="user_does_not_exist"
            ).exists()
        )

        response = c.post("/v2/add_friend/", HTTP_AUTHORIZATION=f"Token {self.token1}")
        self.assertContains(response, "", status_code=400)
        self.assertEqual(self.user1.friend_set.count(), 2)

        # You can't add users who have blocked you
        Friend.objects.create(owner=user4, friend=self.user1, blocked=True)
        response = c.post(
            "/v2/add_friend/",
            {"username": "user4"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        friend: Friend = Friend.objects.get(
            owner__username="user4", friend__username="user1"
        )
        self.assertTrue(friend.blocked)

        token4 = Token.objects.create(user=user4)
        response = c.post(
            "/v2/add_friend/",
            {"username": "user1"},
            HTTP_AUTHORIZATION=f"Token {token4}",
        )
        self.assertContains(response, "", status_code=200)
        friend: Friend = Friend.objects.get(
            owner__username="user4", friend__username="user1"
        )
        self.assertFalse(friend.blocked)
        self.assertFalse(friend.deleted)

    def test_get_friend_name(self):
        c = Client()
        response = c.get(
            "/v2/get_name/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(response.data["data"], {"name": "will smith"})

        Friend.objects.create(owner=self.user1, friend=self.user2, sent=3, name="bro")
        response = c.get(
            "/v2/get_name/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(response.data["data"], {"name": "bro"})

        # check that it still returns a name when one is not manually set
        user4 = get_user_model().objects.create_user(
            username="user4",
            password="my_password4",
            first_name="will",
            last_name="skill",
        )
        Friend.objects.create(owner=self.user1, friend=user4, sent=3)
        response = c.get(
            "/v2/get_name/",
            {"username": "user4"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(response.data["data"], {"name": "will skill"})

        response = c.get("/v2/get_name/", HTTP_AUTHORIZATION=f"Token {self.token1}")
        self.assertContains(response, "", status_code=400)
        response = c.get(
            "/v2/get_name/",
            {"not_username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        response = c.get(
            "/v2/get_name/",
            {"username": "user_does_not_exist"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)

        # You can't look up someone who has blocked you
        Friend.objects.create(owner=user4, friend=self.user1, blocked=True)

        response = c.get(
            "/v2/get_name/",
            {"username": "user4"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)

    def test_block_user(self):
        c = Client()

        # try blocking a user we're currently friends with
        response = c.post(
            "/v2/block_user/",
            {"username": "user1"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).blocked)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)

        Friend.objects.filter(owner=self.user2, friend=self.user1).update(
            blocked=False, deleted=False
        )

        # try blocking a user who is friends with us
        response = c.post(
            "/v2/block_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertTrue(Friend.objects.get(owner=self.user1, friend=self.user2).blocked)
        self.assertTrue(Friend.objects.get(owner=self.user1, friend=self.user2).deleted)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)

        # try blocking ourselves
        response = c.post(
            "/v2/block_user/",
            {"username": "user1"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.filter(
                owner=self.user1, friend=self.user1, blocked=True
            ).exists()
        )

    def test_ignore_user(self):
        c = Client()

        # user1 can ignore user2
        response = c.post(
            "/v2/ignore_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=200)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)

        Friend.objects.filter(owner=self.user2, friend=self.user1).update(deleted=False)
        Friend.objects.create(owner=self.user1, friend=self.user2)

        # now user1 and user2 are friends with each other, user1 can't ignore user2
        response = c.post(
            "/v2/ignore_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.get(owner=self.user2, friend=self.user1).deleted
        )
        self.assertFalse(
            Friend.objects.get(owner=self.user1, friend=self.user2).deleted
        )

        # now user2 isn't friends with user1, so user1 can't ignore them
        Friend.objects.filter(owner=self.user2, friend=self.user1).update(deleted=True)
        Friend.objects.filter(owner=self.user1, friend=self.user2).update(deleted=False)

        response = c.post(
            "/v2/ignore_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)
        self.assertFalse(
            Friend.objects.get(owner=self.user1, friend=self.user2).deleted
        )

        # now neither is friends with the other
        Friend.objects.filter(owner=self.user2, friend=self.user1).update(deleted=True)
        Friend.objects.filter(owner=self.user1, friend=self.user2).update(deleted=True)

        response = c.post(
            "/v2/ignore_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)
        self.assertTrue(Friend.objects.get(owner=self.user1, friend=self.user2).deleted)

        # user2 has blocked user1, so user1 can't tell if user2 exists
        Friend.objects.filter(owner=self.user2, friend=self.user1).update(
            blocked=True, deleted=False
        )
        Friend.objects.filter(owner=self.user1, friend=self.user2).update(deleted=True)

        response = c.post(
            "/v2/ignore_user/",
            {"username": "user2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)
        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).blocked)
        self.assertFalse(
            Friend.objects.get(owner=self.user2, friend=self.user1).deleted
        )
        self.assertTrue(Friend.objects.get(owner=self.user1, friend=self.user2).deleted)

    def test_delete_friend(self):
        c = Client()
        user4 = get_user_model().objects.create_user(
            username="user4",
            password="my_password4",
            first_name="will",
            last_name="smith",
        )
        response = c.delete(
            "/v2/delete_friend/user1/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)

        Friend.objects.filter(owner=self.user2, friend=self.user1).update(deleted=False)
        Friend.objects.update_or_create(
            owner=self.user1, friend=self.user2, defaults={"deleted": False}
        )

        response = c.delete(
            "/v2/delete_friend/user1/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)

        self.assertTrue(Friend.objects.get(owner=self.user2, friend=self.user1).deleted)
        self.assertTrue(Friend.objects.get(owner=self.user1, friend=self.user2).deleted)

        friend = Friend.objects.get(
            owner__username="user2",
            friend__username="user1",
            sent=3,
            received=0,
            deleted=True,
        )

        # User 4 is not friends with us (or vice versa)
        response = c.delete(
            "/v2/delete_friend/user4/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.filter(
                owner__username="user1", friend__username="user4"
            ).exists()
        )

        # user2 is not friends with user4, but user4 is friends with user2
        Friend.objects.create(owner=user4, friend=self.user2)
        response = c.delete(
            "/v2/delete_friend/user4/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.filter(
                owner__username="user1", friend__username="user4"
            ).exists()
        )

        # User does not exist
        response = c.delete(
            "/v2/delete_friend/user_does_not_exist/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)
        self.assertFalse(
            Friend.objects.filter(
                owner__username="user1", friend__username="user_does_not_exist"
            ).exists()
        )

        friend.deleted = False
        friend.save()

        # no username specified in URL
        response = c.delete(
            "/v2/delete_friend/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=404)
        Friend.objects.get(
            owner__username="user2",
            friend__username="user1",
            sent=3,
            received=0,
            deleted=False,
        )

        at_user4 = get_user_model().objects.create_user(
            username="@_user4",
            password="my_password4",
            first_name="will",
            last_name="smith",
        )

        # user2 is friends with @_user4 but @_user4 is not friends with user2
        Friend.objects.create(owner=self.user2, friend=at_user4)
        response = c.delete(
            "/v2/delete_friend/@_user4/",
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        Friend.objects.get(
            owner__username="user2",
            friend__username="@_user4",
            sent=0,
            received=0,
            deleted=True,
        )

    def test_edit_user(self):
        c = Client()
        response = c.put(
            "/v2/edit/",
            {"first_name": "aaron"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "pippin"
        )

        response = c.put(
            "/v2/edit/",
            {"last_name": "adams"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "adams"
        )

        password = get_user_model().objects.get(username="user1").password
        response = c.put(
            "/v2/edit/",
            {"password": "password", "old_password": "my_password"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "adams"
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, "password"
        )
        self.token1 = Token.objects.get(user=self.user1)

        response = c.put(
            "/v2/edit/",
            {"email": "valid@example.com"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "adams"
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, "password"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").email, "valid@example.com"
        )

        response = c.put(
            "/v2/edit/",
            {"email": "in valid@example.com"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "adams"
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, "password"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").email, "valid@example.com"
        )

        response = c.put(
            "/v2/edit/",
            {
                "last_name": "last",
                "first_name": "first",
                "password": "new_pass",
                "email": "invalid",
                "old_password": "password",
            },
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "aaron"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "adams"
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, "password"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").email, "valid@example.com"
        )

        password = get_user_model().objects.get(username="user1").password
        response = c.put(
            "/v2/edit/",
            {
                "last_name": "last",
                "first_name": "first",
                "password": "new_pass",
                "old_password": "password",
            },
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "first"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "last"
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, "new_pass"
        )
        self.token1 = Token.objects.get(user=self.user1)

        response = c.put(
            "/v2/edit/",
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "first"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "last"
        )

        password = get_user_model().objects.get(username="user1").password
        # the password for user1 is now new_pass, so password will fail
        response = c.put(
            "/v2/edit/",
            {
                "last_name": "diff",
                "first_name": "diifff",
                "password": 'won"t pass',
                "old_password": "password",
            },
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=401)
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "first"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "last"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, 'wont"t pass'
        )

        password = get_user_model().objects.get(username="user1").password
        response = c.put(
            "/v2/edit/",
            {
                "last_name": "blljdf",
                "first_name": "adfqefedf fda",
                "password": 'won"t pass',
            },
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)  # no old_password parameter
        self.assertEqual(
            get_user_model().objects.get(username="user1").first_name, "first"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").last_name, "last"
        )
        self.assertEqual(
            get_user_model().objects.get(username="user1").password, password
        )
        self.assertNotEqual(
            get_user_model().objects.get(username="user1").password, 'wont"t pass'
        )

        user3 = get_user_model().objects.create_user(
            username="user3", first_name="roly", last_name="poly", password=None
        )
        token3 = Token.objects.create(user=user3)
        response = c.put(
            "/v2/edit/",
            {"old_password": "", "password": "password"},
            HTTP_AUTHORIZATION=f"Token {token3}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=401)  # password is new_pass
        response = c.put(
            "/v2/edit/",
            {"old_password": None, "password": "password"},
            HTTP_AUTHORIZATION=f"Token {token3}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=401)  # password is new_pass
        response = c.put(
            "/v2/edit/",
            {"old_password": "password", "password": "new_password"},
            HTTP_AUTHORIZATION=f"Token {token3}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=401)  # password is new_pass

    def test_photos(self):
        with open(TEST_PHOTO_DIR / "photo1.JPG", "rb") as f:
            self.verifyPhoto(self.user1, self.token1, f)
        with open(TEST_PHOTO_DIR / "photo2.JPG", "rb") as f:
            self.verifyPhoto(self.user1, self.token1, f)
        temp_photo = Photo.objects.get(user=self.user1).photo
        with open(TEST_PHOTO_DIR / "photo3.JPG", "rb") as f:
            self.verifyPhoto(self.user2, self.token2, f)
        self.assertEqual(Photo.objects.filter(user=self.user1).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user1).photo,
            temp_photo,
            "Updating another user's photo should not impact existing photos",
        )
        with open(TEST_PHOTO_DIR / "photo4.jpg", "rb") as f:
            self.verifyPhoto(self.user2, self.token2, f)
        self.assertEqual(Photo.objects.filter(user=self.user1).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user1).photo,
            temp_photo,
            "Updating another user's photo should not impact existing photos",
        )
        with open(TEST_PHOTO_DIR / "photo5.JPG", "rb") as f:
            self.verifyPhoto(self.user2, self.token2, f)
        self.assertEqual(Photo.objects.filter(user=self.user1).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user1).photo,
            temp_photo,
            "Updating another user's photo should not impact existing photos",
        )
        temp_photo = Photo.objects.get(user=self.user2).photo
        with open(TEST_PHOTO_DIR / "gif.gif", "rb") as f:
            self.verifyPhoto(self.user1, self.token1, f)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "Updating another user's photo should not impact existing photos",
        )
        with open(TEST_PHOTO_DIR / "small_gif.gif", "rb") as f:
            self.verifyPhoto(self.user1, self.token1, f)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "Updating another user's photo should not impact existing photos",
        )

        c = (
            APIClient()
        )  # this should return file too large (file exceeds ~200 megapixel limit without exceeding 20 MB
        # limit)
        with open(TEST_PHOTO_DIR / "decompression_bomb.png", "rb") as f:
            response = c.put(
                "/v2/photo/",
                {"photo": f},
                HTTP_AUTHORIZATION=f"Token {self.token2}",
                format="multipart",
            )
            print(response.data)
            self.assertContains(response, "", status_code=413)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "A failed update should not change the photo",
        )

        # this file exceeds the 20 MB limit
        with open(TEST_PHOTO_DIR / "too_large.png", "rb") as f:
            response = c.put(
                "/v2/photo/",
                {"photo": f},
                HTTP_AUTHORIZATION=f"Token {self.token2}",
                format="multipart",
            )
            self.assertContains(response, "", status_code=400)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "A failed update should not change the photo",
        )

        # this file isn't a photo
        with open(TEST_PHOTO_DIR / "not_a_photo.txt", "rb") as f:
            response = c.put(
                "/v2/photo/",
                {"photo": f},
                HTTP_AUTHORIZATION=f"Token {self.token2}",
                format="multipart",
            )
            self.assertContains(response, "", status_code=400)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "A failed update should not change the photo",
        )

        # this file isn't a photo
        with open(TEST_PHOTO_DIR / "not_a_photo.png", "rb") as f:
            response = c.put(
                "/v2/photo/",
                {"photo": f},
                HTTP_AUTHORIZATION=f"Token {self.token2}",
                format="multipart",
            )
            self.assertContains(response, "", status_code=400)
        self.assertEqual(Photo.objects.filter(user=self.user2).count(), 1)
        self.assertEqual(
            Photo.objects.get(user=self.user2).photo,
            temp_photo,
            "A failed update should not change the photo",
        )

    def test_get_user_info(self):
        # dump the user info, check it all matches
        self.maxDiff = None
        c = Client()

        # user2 -> user1
        user4 = get_user_model().objects.create_user(
            username="user4",
            password="my_password4",
            first_name="will",
            last_name="smith",
        )
        f_user4 = Friend.objects.create(owner=self.user2, friend=user4, deleted=True)
        Friend.objects.create(owner=self.user1, friend=self.user2)

        # user1 <-> user2
        # basic test
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    }
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        Friend.objects.create(owner=user4, friend=self.user2)
        f_user4.deleted = False
        f_user4.save()

        # user1 <-> user2, user2 <-> user4
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user4",
                        "name": "will smith",
                        "sent": 0,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        f_user4.blocked = True
        f_user4.save()

        # user1 <-> user2, user2 <-! user4 (user4 shouldn't show up in pending friends because user2 blocked them)
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    }
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        user5 = get_user_model().objects.create_user(
            username="user5",
            password="my_password5",
            first_name="smill",
            last_name="pill",
        )

        Friend.objects.create(friend=self.user2, owner=user5, deleted=False, sent=0)
        # user1 <-> user2, user2 <-! user4, user2 <- user5
        # check that pending friends show up
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [
                    {"username": "user5", "name": "smill pill", "photo": None}
                ],
            },
            response.data["data"],
        )

        Friend.objects.create(owner=self.user2, friend=user5, deleted=True, sent=5)

        # user1 <-> user2, user2 <-! user4, user2 <- user5
        # check that deleted friends show up in pending friends
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [
                    {"username": "user5", "name": "smill pill", "photo": None}
                ],
            },
            response.data["data"],
        )

        Friend.objects.filter(owner=self.user2, friend=user5).update(
            deleted=False, blocked=True
        )

        # user1 <-> user2, user2 <-! user4, user2 <-! user5
        # check that blocked users don't show up in pending friends, even if they aren't marked as deleted
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        Friend.objects.filter(owner=self.user2, friend=user5).update(
            deleted=False, blocked=False
        )

        # user1 <-> user2, user2 <-! user4, user2 <-> user5
        user6 = get_user_model().objects.create_user(
            username="user6",
            password="my_password5",
            first_name="smell",
            last_name="pell",
        )
        f6 = Friend.objects.create(
            owner=self.user2, friend=user6, deleted=False, sent=2
        )
        Friend.objects.create(friend=self.user2, owner=user6, deleted=False, sent=0)
        f_user4.sent = 7
        f_user4.save()

        # user1 <-> user2, user2 <-! user4, user2 <-> user5, user2 <-> user6
        # check that results are sorted in the correct order
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user5",
                        "name": "smill pill",
                        "sent": 5,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user6",
                        "name": "smell pell",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        f6.name = "smelly feet"
        f6.save()

        # check that custom names show up correctly
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user5",
                        "name": "smill pill",
                        "sent": 5,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user6",
                        "name": "smelly feet",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        f6.name = None
        f6.save()

        Photo.objects.create(user=user5, photo="test")

        # check that friends' photos show up correctly
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user5",
                        "name": "smill pill",
                        "sent": 5,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": "test",
                    },
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user6",
                        "name": "smell pell",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        Friend.objects.filter(owner=self.user2, friend=user5).update(deleted=True)

        # user1 <- user2, user2 <-! user4, user2 <-x user5, user2 <-> user6
        # check that pending friends' photos show up correctly
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": None,
                "friends": [
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user6",
                        "name": "smell pell",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [
                    {"username": "user5", "name": "smill pill", "photo": "test"}
                ],
            },
            response.data["data"],
        )

        Friend.objects.filter(owner=self.user2, friend=user5).update(deleted=False)
        Photo.objects.create(user=self.user2, photo="test2")

        # user1 <- user2, user2 <-! user4, user2 <-> user5, user2 <-> user6
        # check that the user's photo shows up correctly
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": "test2",
                "friends": [
                    {
                        "username": "user5",
                        "name": "smill pill",
                        "sent": 5,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": "test",
                    },
                    {
                        "username": "user1",
                        "name": "poppin pippin",
                        "sent": 3,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                    {
                        "username": "user6",
                        "name": "smell pell",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

        Friend.objects.filter(owner=self.user1, friend=self.user2).update(deleted=True)
        Friend.objects.create(owner=self.user1, friend=user5)
        Friend.objects.create(owner=user5, friend=self.user1)
        # user1 <- user2, user2 <-! user4, user2 <-> user5, user2 <-> user6, user1 <-> user5

        # check that irrelevant friendships (user1 and user5) don't impact the results
        response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {self.token2}")
        self.assertContains(response, "", status_code=200)
        self.assertEqual(
            {
                "username": "user2",
                "first_name": "will",
                "last_name": "smith",
                "email": "test@sample.verify",
                "password_login": True,
                "photo": "test2",
                "friends": [
                    {
                        "username": "user5",
                        "name": "smill pill",
                        "sent": 5,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": "test",
                    },
                    {
                        "username": "user6",
                        "name": "smell pell",
                        "sent": 2,
                        "received": 0,
                        "last_message_id_sent": None,
                        "last_message_status": None,
                        "photo": None,
                    },
                ],
                "pending_friends": [],
            },
            response.data["data"],
        )

    def test_edit_friend_name(self):
        # editing the friend name for a friend that doesn't exist creates a friend that is deleted
        c = Client()
        response = c.put(
            "/v2/edit_friend_name/",
            {"username": "user2", "new_name": "duuude"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertTrue(
            Friend.objects.filter(
                owner=self.user1, friend=self.user2, name="duuude", deleted=True
            ).exists()
        )

        # editing a friend name updates the friend name
        response = c.put(
            "/v2/edit_friend_name/",
            {"username": "user1", "new_name": "will slaps"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertTrue(
            Friend.objects.filter(
                owner=self.user2, friend=self.user1, name="will slaps", deleted=False
            ).exists()
        )

    def test_delete_user_info(self):
        # no username/password
        c = Client()
        response = c.delete(
            "/v2/delete_user_data/",
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=400)

        # username/password but belonging to a different user than the token
        response = c.delete(
            "/v2/delete_user_data/",
            {"username": "user2", "password": "my_password2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=403)

        # username and token match, but wrong password
        response = c.delete(
            "/v2/delete_user_data/",
            {"username": "user1", "password": "my_password2"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=403)

        Friend.objects.create(owner=self.user1, friend=self.user2)
        # correct match: verify user.object.filter(...).exists() is false, but also the friend relationships in both
        # directions
        response = c.delete(
            "/v2/delete_user_data/",
            {"username": "user2", "password": "my_password2"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
            content_type="application/json",
        )
        self.assertContains(response, "", status_code=200)
        self.assertFalse(get_user_model().objects.filter(username="user2").exists())
        self.assertFalse(Friend.objects.filter(owner=self.user2).exists())
        self.assertFalse(Friend.objects.filter(friend=self.user2).exists())

    def test_send_alert(self):
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
        response = c.get(
            "/v2/send_alert/",
            {"to": "user2", "message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=405)

        # Missing 'to' parameter
        response = c.post(
            "/v2/send_alert/",
            {"message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token1}",
        )
        self.assertContains(response, "", status_code=400)

        # Test that you can't send messages to people who don't have you as a friend
        response = c.post(
            "/v2/send_alert/",
            {"to": "user1", "message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
        )
        self.assertContains(response, "", status_code=403)

        # Test that deleted friends can't receive messages
        Friend.objects.create(owner=self.user1, friend=self.user2, deleted=True)
        response = c.post(
            "/v2/send_alert/",
            {"to": "user1", "message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
        )
        self.assertContains(response, "", status_code=403)

        # Test that you can't receive messages from someone you blocked
        Friend.objects.filter(owner=self.user1, friend=self.user2).update(blocked=True)
        response = c.post(
            "/v2/send_alert/",
            {"to": "user1", "message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
        )
        self.assertContains(response, "", status_code=403)

        # Test that you can't receive messages from someone you blocked (even if deleted is False)
        Friend.objects.filter(owner=self.user1, friend=self.user2).update(deleted=False)
        response = c.post(
            "/v2/send_alert/",
            {"to": "user1", "message": "hi"},
            HTTP_AUTHORIZATION=f"Token {self.token2}",
        )
        self.assertContains(response, "", status_code=403)

    def test_check_params_simple(self):
        """
        Just pass a bunch and check that the missing params line up, that it returns False each time something isn't
        right, returns True whenever all params are present
        Should also return True when more params than necessary passed
        """
        empty_dict = {}
        simple_dict = {"param1": "val1", "param2": "val2", "param3": "val3"}
        big_dict = {
            "to": "TO this person",
            "from": "FROM this person",
            "signature": "I've signed this",
            "challenge": "This is what I signed",
            "message": "This is what I want to say",
            "id": "This is an ID",
            "token": "This is a token",
        }

        list_empty = []
        list_params = ["param1", "param2", "param3"]
        list_params_extra = ["param1", "param2", "param3", "param4"]
        list_params_fewer = ["param2", "param3"]

        list_values = ["signature", "challenge", "from", "to", "message", "id", "token"]
        list_some_values = ["signature", "from", "to", "message", "challenge"]

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
        self.assertIn("param4", response.data["message"])
        self.assertEqual(response.status_code, 400)
        good, response = check_params(list_params, empty_dict)
        self.assertFalse(good)
        self.assertIn("param1", response.data["message"])
        self.assertIn("param2", response.data["message"])
        self.assertIn("param3", response.data["message"])
        self.assertEqual(response.status_code, 400)

    def test_check_params_weird(self):
        weird_dict = {
            "": "Empty key",
            "key1": 1,
            "key2": "Normal key-value",
            "key3": None,
            "key4": 3.14,
            "key5": {"key5_0": "", "key5_1": "another one?"},
            "key6": "",
            "key7": ["value1", "value2", 3, None, 3.14, ""],
        }

        list_keys = ["key1", "", "key6", "key7", "key1", "key2", "key3", "key4", "key5"]
        list_keys_extra = [
            "key1",
            "",
            "key6",
            "key7",
            "key1",
            "key2",
            "key3",
            "key4",
            "key5",
            "key5_0",
        ]

        good, response = check_params(list_keys, weird_dict)
        self.assertTrue(good)
        good, response = check_params(list_keys_extra, weird_dict)
        self.assertFalse(good)
        self.assertIn("key5_0", response.data["message"])
        self.assertEqual(response.status_code, 400)

    def test_private_functions_private(self):
        c = Client()
        response = c.get("/v2/verify_signature/")
        self.assertContains(response, "", status_code=404)
        response = c.get("/v2/check_params/")
        self.assertContains(response, "", status_code=404)
        response = c.get("/v2/build_response/")
        self.assertContains(response, "", status_code=404)
        response = c.get("/v2/string_response/")
        self.assertContains(response, "", status_code=404)
        response = c.get("/v2/verify_challenge/")
        self.assertContains(response, "", status_code=404)

    def test_auth_enforced(self):
        c = Client()
        for endpoint in auth_required_post_endpoints:
            response = c.post(f"/v2/{endpoint}/")
            self.assertContains(response, "", status_code=403)
            response = c.post(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token notavalidtoken"
            )
            self.assertContains(response, "", status_code=403)

            response = c.get(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.put(
                f"/v2/{endpoint}/",
                HTTP_AUTHORIZATION=f"Token {self.token1}",
                content_type="application/json",
            )
            self.assertContains(response, "", status_code=405)
            response = c.delete(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.patch(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)

        for endpoint in auth_required_get_endpoints:
            response = c.get(f"/v2/{endpoint}/")
            self.assertContains(response, "", status_code=403)
            response = c.get(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token notavalidtoken"
            )
            self.assertContains(response, "", status_code=403)

            response = c.post(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.put(
                f"/v2/{endpoint}/",
                HTTP_AUTHORIZATION=f"Token {self.token1}",
                content_type="application/json",
            )
            self.assertContains(response, "", status_code=405)
            response = c.delete(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.patch(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)

        for endpoint in auth_required_delete_endpoints:
            response = c.delete(f"/v2/{endpoint}/")
            self.assertContains(response, "", status_code=403)
            response = c.delete(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token notavalidtoken"
            )
            self.assertContains(response, "", status_code=403)

            response = c.get(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.put(
                f"/v2/{endpoint}/",
                HTTP_AUTHORIZATION=f"Token {self.token1}",
                content_type="application/json",
            )
            self.assertContains(response, "", status_code=405)
            response = c.post(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.patch(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)

        for endpoint in auth_required_put_endpoints:
            response = c.put(f"/v2/{endpoint}/", content_type="application/json")
            self.assertContains(response, "", status_code=403)
            response = c.put(
                f"/v2/{endpoint}/",
                HTTP_AUTHORIZATION=f"Token notavalidtoken",
                content_type="application/json",
            )
            self.assertContains(response, "", status_code=403)

            response = c.get(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.post(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.delete(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)
            response = c.patch(
                f"/v2/{endpoint}/", HTTP_AUTHORIZATION=f"Token {self.token1}"
            )
            self.assertContains(response, "", status_code=405)

    def test_api_integration(self):

        def get_tokens():
            for inner_user in users:
                inner_response = c.post(
                    f"/v2/api_token_auth/",
                    {"username": inner_user[0], "password": inner_user[1]},
                )
                self.assertContains(inner_response, "", status_code=200)
                inner_response_json = inner_response.data
                inner_user[4] = inner_response_json["token"]

        c = Client()
        num_users: Final = 50

        # Stores the users that are available - each element should be [private key, challenge]
        users: list[list] = []
        # Generate some users
        for x in range(num_users):
            users.append(
                [
                    f"test_user_{x}",
                    f"test_password_{x}",
                    f"test_first_name_{x}",
                    f"test_last_name_{x}",
                    None,
                ]
            )
            response = c.post(
                "/v2/register_user/",
                {
                    "username": users[x][0],
                    "password": users[x][1],
                    "first_name": users[x][2],
                    "last_name": users[x][3],
                    "tos_agree": "yes",
                },
            )
            self.assertContains(response, "", status_code=200)

        # Get challenges for the users
        get_tokens()

        # Update the users with the new tokens
        for username, password, first_name, last_name, token in users:
            response = c.put(
                "/v2/edit/",
                {"first_name": first_name + "update"},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Token {token}",
            )
            self.assertContains(response, "", status_code=200)

        # Check that it still works
        for username, password, first_name, last_name, token in users:
            response = c.get("/v2/get_info/", HTTP_AUTHORIZATION=f"Token {token}")
            self.assertContains(response, "", status_code=200)

        # Change passwords
        for x in range(len(users)):
            token = users[x][4]
            old_pass = users[x][1]
            users[x][1] += "updated"
            response = c.put(
                "/v2/edit/",
                {"password": users[x][1], "old_password": old_pass},
                HTTP_AUTHORIZATION=f"Token {token}",
                content_type=get_content_type(),
            )
            self.assertContains(response, "", status_code=200)

        # Token should no longer be valid
        for username, password, first_name, last_name, token in users:
            response = c.post(
                "/v2/register_device/",
                {"fcm_token": "fake_token"},
                HTTP_AUTHORIZATION=f"Token {token}",
                content_type=get_content_type(),
            )
            self.assertContains(response, "", status_code=403)

        get_tokens()

        # Tokens should work now
        for username, password, first_name, last_name, token in users:
            response = c.post(
                "/v2/add_friend/",
                {"username": random.choice(users)[0]},
                HTTP_AUTHORIZATION=f"Token {token}",
                content_type=get_content_type(),
            )
            self.assertContains(response, "", status_code=200)

        for username, password, first_name, last_name, token in users:
            response = c.delete(
                "/v2/delete_user_data/",
                {"username": username, "password": password},
                HTTP_AUTHORIZATION=f"Token {token}",
                content_type=get_content_type(),
            )
            self.assertContains(response, "", status_code=200)
            self.assertFalse(
                get_user_model().objects.filter(username=username).exists()
            )
            self.assertFalse(Friend.objects.filter(owner__username=username).exists())
            self.assertFalse(Friend.objects.filter(friend__username=username).exists())
            self.assertFalse(Token.objects.filter(user__username=username).exists())

    def assertFriendEqual(self, expected: Friend, actual: Friend):
        self.assertEqual(expected.pk, actual.pk)
        self.assertEqual(expected.owner, actual.owner)
        self.assertEqual(expected.friend, actual.friend)
        self.assertEqual(expected.sent, actual.sent)
        self.assertEqual(expected.name, actual.name)
        self.assertEqual(expected.received, actual.received)
        self.assertEqual(expected.deleted, actual.deleted)

    def verifyPhoto(self, user, token, photo):
        c = APIClient()

        response = c.put(
            "/v2/photo/",
            data={"photo": photo},
            HTTP_AUTHORIZATION=f"Token {token}",
            format="multipart",
        )
        print(response.data)
        self.assertContains(response, "", status_code=200)
        self.assertEqual(Photo.objects.filter(user=user).count(), 1)
        photo_data = Photo.objects.get(user=user).photo
        temp_photo: Image.Image = Image.open(io.BytesIO(base64.b64decode(photo_data)))
        self.assertEqual(temp_photo.size, (Photo.PHOTO_SIZE, Photo.PHOTO_SIZE))
        # temp_photo.show()
        # Image.open(photo).show()
        response = c.get(
            "/v2/get_info/",
            HTTP_AUTHORIZATION=f"Token {token}",
            content_type=get_content_type(),
        )
        self.assertEqual(response.data["data"]["photo"], photo_data)


def get_content_type():
    return "application/json"
