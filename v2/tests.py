from django.test import TestCase

# Create your tests here.


class APIV2TestSuite(TestCase):

    def setUp(self):
        pass

    def test_add_user(self):
        """
        This should test upload_public_key
        Use both POST and PUT
        Add a user, update it, make sure a new one wasn't created
        Test malformed requests (missing required parameters, too many parameters, etc.)
        Check status codes
        """
        pass

    def test_get_challenge(self):
        """
        This should test get_challenge
        Request a challenge, make sure the one in the database is the same as the one returned
        Test with invalid public_keys (or missing parameters)
        Make sure no two challenges are the same
        Check status codes
        """
        pass

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

    def test_check_params(self):
        """
        Just pass a bunch and check that the missing params line up, that it returns False each time something isn't
        right, returns True whenever all params are present
        Should also return True when more params than necessary passed
        """
        pass
