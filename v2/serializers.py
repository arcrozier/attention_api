from rest_framework import serializers

from v2.models import Friend


class FriendSerializer(serializers.ModelSerializer):
    class Meta:
        model = Friend
        fields = ['owner', 'friend', 'sent', 'received']
