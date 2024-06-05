from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth import authenticate
from .serializers import (
    AdminSerializer,
    LoginSerializer,
    ManagerSerializer,
    UserSerializer,
    RoomSerializer,
)
from .models import Hotel, Rooms
from .permissions import IsAdminOrNot, IsManagerOrNot, IsUserOrNot
from .authentication import JWTAuthentication
from .jwt_utils import generate_jwt_token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import BasicAuthentication

# Create your views here.


# class AdminRegisterApiView(generics.CreateAPIView):
#     serializer_class = AdminSerializer
#     permission_classes = [AllowAny]

#     def create(self, request, *args, **kwargs):
#         data = request.data
#         data["role"] = "A"
#         serializer = self.get_serializer(data=data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_201_CREATED)


"""
------------------Admin view----------------------------------
"""


class AdminLoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        admin = authenticate(
            request,
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if admin:
            if admin.role == "A":
                return Response(
                    {"msg": "Admin login successful..."}, status=status.HTTP_200_OK
                )
            return Response(
                {"msg": "this is not admin credentials..."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response(
            {"msg": "invalid credentials..."}, status=status.HTTP_401_UNAUTHORIZED
        )


class AddManagerApiView(generics.ListCreateAPIView):
    serializer_class = ManagerSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]

    def get_queryset(self):
        return Hotel.objects.filter(role="M").all()


class ManageManagerDetailsApiView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ManagerSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]
    queryset = Hotel.objects.all()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "M":
            serializer = self.get_serializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(
            {"msg": "Invalid Manager id"}, status=status.HTTP_400_BAD_REQUEST
        )

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "M":
            serializer = self.get_serializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(
            {"msg": "Invalid Manager id"}, status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "M":
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(
            {"msg": "Invalid Manager id"}, status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "M":
            self.perform_destroy(instance)
            return Response(
                {"msg": "Manager Deleted..."}, status=status.HTTP_204_NO_CONTENT
            )
        return Response(
            {"msg": "Invalid Manager id"}, status=status.HTTP_400_BAD_REQUEST
        )


class AddUserByAdminApiView(generics.ListCreateAPIView):
    serializer_class = UserSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]

    def get_queryset(self):
        return Hotel.objects.filter(role="U").all()


class ManageUserDetailsByAdminApiView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]
    queryset = Hotel.objects.all()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "U":
            serializer = self.get_serializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "U":
            serializer = self.get_serializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "U":
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role == "U":
            self.perform_destroy(instance)
            return Response(
                {"msg": "User Deleted..."}, status=status.HTTP_204_NO_CONTENT
            )
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)


class AddRoomAndListByAdminApiView(generics.ListCreateAPIView):
    serializer_class = RoomSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]
    queryset = Rooms.objects.all()


class ManagerRoomsByAdminApiView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RoomSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]
    queryset = Rooms.objects.all()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"msg": "Room Deleted..."}, status=status.HTTP_204_NO_CONTENT)


class CheckInByAdminApiView(generics.UpdateAPIView):
    serializer_class = RoomSerializer
    permission_classes = [IsAdminOrNot]
    authentication_classes = [BasicAuthentication]
    queryset = Rooms.objects.all()

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        data = request.data
        user_id = data.get("user")  # Correct the typo here
        try:
            user = Hotel.objects.get(id=user_id)
        except Hotel.DoesNotExist:
            return Response(
                {"msg": "User not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        if user.role == "U":
            print(instance.user)
            if instance.user is None:
                serializer = self.get_serializer(instance, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(
                {"msg": "room not avilable"}, status=status.HTTP_400_BAD_REQUEST
            )
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)


class CheckOutByAdminApiView(generics.UpdateAPIView):
    serializer_class = RoomSerializer
    permission_classes = [IsAdminOrNot]
    authentication_classes = [BasicAuthentication]
    queryset = Rooms.objects.all()

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        data = request.data
        user_id = data.get("user")  # Correct the typo here
        try:
            user = Hotel.objects.get(id=user_id)
        except Hotel.DoesNotExist:
            return Response(
                {"msg": "User not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        if user.role == "U" and instance.user_id == user.id:
            data["user"] = None
            serializer = self.get_serializer(instance, data=data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"msg": "Check out done..."}, status=status.HTTP_200_OK)
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)


"""
---------------------Manager view-----------------------------
"""


class ManagerRegisterApiView(generics.CreateAPIView):
    serializer_class = ManagerSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        data = request.data
        data["role"] = "M"
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ManagerLoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        manager = authenticate(
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if manager:
            if manager.role == "M":
                token = generate_jwt_token(user_id=manager.id)
                return Response(
                    {"msg": "Manager login successful...", "Token": token},
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"msg": "this is not Manager credentials..."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class GetManagerDetailsApiView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ManagerSerializer
    permission_classes = [IsManagerOrNot]
    authentication_classes = [JWTAuthentication]
    queryset = Hotel.objects.all()

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"msg": "Manager Deleted..."}, status=status.HTTP_204_NO_CONTENT
        )


class AddUserByManagerApiView(generics.ListCreateAPIView):
    serializer_class = UserSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminOrNot]

    def get_queryset(self):
        return Hotel.objects.filter(role="U").all()


class AddRoomByManager(generics.ListCreateAPIView):
    serializer_class = RoomSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsManagerOrNot]
    queryset = Rooms.objects.all()


class CheckInByManagerApiView(generics.UpdateAPIView):
    serializer_class = RoomSerializer
    permission_classes = [IsManagerOrNot]
    authentication_classes = [JWTAuthentication]
    queryset = Rooms.objects.all()

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        data = request.data
        user_id = data.get("user")  # Correct the typo here
        try:
            user = Hotel.objects.get(id=user_id)
        except Hotel.DoesNotExist:
            return Response(
                {"msg": "User not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        if user.role == "U":
            print(instance.user)
            if instance.user is None:
                serializer = self.get_serializer(instance, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(
                {"msg": "room not avilable"}, status=status.HTTP_400_BAD_REQUEST
            )
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)


class CheckOutByManagerApiView(generics.UpdateAPIView):
    serializer_class = RoomSerializer
    permission_classes = [IsManagerOrNot]
    authentication_classes = [JWTAuthentication]
    queryset = Rooms.objects.all()

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        data = request.data
        user_id = data.get("user")  # Correct the typo here
        try:
            user = Hotel.objects.get(id=user_id)
        except Hotel.DoesNotExist:
            return Response(
                {"msg": "User not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        if user.role == "U" and instance.user_id == user.id:
            data["user"] = None
            serializer = self.get_serializer(instance, data=data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"msg": "Check out done..."}, status=status.HTTP_200_OK)
        return Response({"msg": "Invalid User id"}, status=status.HTTP_400_BAD_REQUEST)


"""
---------------------------User view--------------------------------
"""


class UserRegisterApiView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        data = request.data
        data["role"] = "U"
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UserLoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if user:
            if user.role == "U":
                token = generate_jwt_token(user_id=user.id)
                return Response(
                    {"msg": "User login successful...", "Token": token},
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"msg": "this is not user credentials..."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class GetUserDetailsApiView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsUserOrNot]
    authentication_classes = [JWTAuthentication]
    queryset = Hotel.objects.all()

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"msg": "User Deleted..."}, status=status.HTTP_204_NO_CONTENT
        )

class GetAvailableRoomDetailsApiView(generics.ListAPIView):
    serializer_class = RoomSerializer

    def get_queryset(self):
        return Rooms.objects.filter(user_id__isnull=True)
