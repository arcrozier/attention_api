# Generated by Django 4.0.3 on 2022-04-24 20:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('v2', '0002_friend_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='friend',
            name='name',
            field=models.CharField(default='', max_length=150),
        ),
    ]
