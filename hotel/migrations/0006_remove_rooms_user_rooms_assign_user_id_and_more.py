# Generated by Django 5.0.4 on 2024-05-10 07:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hotel', '0005_alter_hotel_phone_alter_rooms_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='rooms',
            name='user',
        ),
        migrations.AddField(
            model_name='rooms',
            name='assign_user_id',
            field=models.IntegerField(null=True),
        ),
    ]