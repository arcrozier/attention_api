# Generated by Django 4.0.4 on 2022-06-15 06:18

from django.db import migrations


def nullify_blank(v2, _):
    model = v2.get_model('v2', 'user')
    for row in model.objects.all():
        if row.email == '':
            row.email = None
            row.save(update_fields=['email'])


class Migration(migrations.Migration):

    dependencies = [
        ('v2', '0002_alter_user_email_alter_user_username'),
    ]

    operations = [
        migrations.RunPython(nullify_blank, reverse_code=migrations.RunPython.noop)
    ]
