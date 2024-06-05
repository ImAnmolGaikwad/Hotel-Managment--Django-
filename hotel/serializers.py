from rest_framework import serializers
from .models import Hotel, Rooms
import re


class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hotel
        fields = ["id", "first_name", "email", "username", "password", "role"]

    def update(self, instance, validated_data):
        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get("first_name", instance.first_name)
        new_password = validated_data.get("password")
        if new_password:
            instance.set_password(new_password)
        instance.save()
        return instance

    def validate(self, attrs):
        error = {}
        if not re.match(r"^[\S][a-zA-Z\s]{1,}$", attrs["first_name"]):
            error.update({"first_nameError": "first_name contain only characters"})
        if not re.match(
            r"^(?=.*[\d])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,25}$",
            attrs["password"],
        ):
            error.update(
                {
                    "passwordError": "Password must contain one lowercase, one uppercase, one digit and one spacial character and min length 8"
                }
            )
        if error:
            raise serializers.ValidationError(error)
        return attrs


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class ManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hotel
        fields = ["id", "first_name", "email", "username", "password", "role", "phone"]

    def update(self, instance, validated_data):
        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.phone = validated_data.get("phone", instance.phone)
        new_password = validated_data.get("password")
        if new_password:
            instance.set_password(new_password)
        instance.save()
        return instance

    def validate(self, attrs):
        error = {}
        if not re.match(r"^[\S][a-zA-Z\s]{1,}$", attrs["first_name"]):
            error.update({"first_nameError": "first_name contain only characters"})
        if not re.match(
            r"^(?=.*[\d])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,25}$",
            attrs["password"],
        ):
            error.update(
                {
                    "passwordError": "Password must contain one lowercase, one uppercase, one digit and one spacial character and min length 8"
                }
            )
        if not re.match(r"^[6-9][\d]{9}$", str(attrs["phone"])):
            error.update(
                {"phoneError": "number must have 10 digit and starts with 6,7,8 and 9"}
            )
        if error:
            raise serializers.ValidationError(error)
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hotel
        fields = ["id", "first_name", "email", "username", "password", "role", "phone"]

    def update(self, instance, validated_data):
        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.phone = validated_data.get("phone", instance.phone)
        new_password = validated_data.get("password")
        if new_password:
            instance.set_password(new_password)
        instance.save()
        return instance

    def validate(self, attrs):
        error = {}
        if not re.match(r"^[\S][a-zA-Z\s]{1,}$", attrs["first_name"]):
            error.update({"first_nameError": "first_name contain only characters"})
        if not re.match(
            r"^(?=.*[\d])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,25}$",
            attrs["password"],
        ):
            error.update(
                {
                    "passwordError": "Password must contain one lowercase, one uppercase, one digit and one spacial character and min length 8"
                }
            )
        if not re.match(r"^[6-9][\d]{9}$", str(attrs["phone"])):
            error.update(
                {"phoneError": "number must have 10 digit and starts with 6,7,8 and 9"}
            )
        if error:
            raise serializers.ValidationError(error)
        return attrs


class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rooms
        fields = "__all__"

    def update(self, instance, validated_data):
        instance.type = validated_data.get("type", instance.type)
        instance.charges = validated_data.get("charges", instance.charges)
        instance.user = validated_data.get("user", instance.user)
        instance.save()

        return instance
