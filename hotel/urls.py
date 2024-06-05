from django.urls import path
from .views import (
    AddManagerApiView,
    AddRoomAndListByAdminApiView,
    GetAvailableRoomDetailsApiView,
    ManagerRegisterApiView,
    ManagerLoginApiView,
    AdminLoginApiView,
    GetManagerDetailsApiView,
    AddRoomByManager,
    UserLoginApiView,
    UserRegisterApiView,
    AddUserByAdminApiView,
    AddUserByManagerApiView,
    GetUserDetailsApiView,
    ManageManagerDetailsApiView,
    ManageUserDetailsByAdminApiView,
    CheckInByAdminApiView,
    CheckOutByAdminApiView,
    CheckInByManagerApiView,
    CheckOutByManagerApiView
)

urlpatterns = [
    #Admin Urls
    path('admin/login/',AdminLoginApiView.as_view(),name='admin login'),
    path("admin/addManager/", AddManagerApiView.as_view(), name="add manager by admin"),
    path('admin/addRoom/',AddRoomAndListByAdminApiView.as_view(),name='add room by admin'),
    path('admin/addUser/',AddUserByAdminApiView.as_view(),name='add user by admin'),
    path('admin/manageManager/<int:pk>',ManageManagerDetailsApiView.as_view(),name='manage manager by admin'),
    path('admin/manageUser/<int:pk>',ManageUserDetailsByAdminApiView.as_view(),name='manage user by admin'),
    path('admin/checkIn/<int:pk>/',CheckInByAdminApiView.as_view(),name='check in by admin'),
    path('admin/checkOut/<int:pk>/',CheckOutByAdminApiView.as_view(),name='check out by admin'),
    #Manager Urls
    path('manager/login/',ManagerLoginApiView.as_view(),name='manager login'),
    path('manager/register/',ManagerRegisterApiView.as_view(),name='manager register'),
    path('manager/get/',GetManagerDetailsApiView.as_view(),name='get manager details'),
    path('manager/addUser/',AddUserByManagerApiView.as_view,name='add user by manager'),
    path('manager/addRoom/',AddRoomByManager.as_view(),name='add room by manager'),
    path('manager/checkIn/<int:pk>/',CheckInByManagerApiView.as_view(),name='check in by manager'),
    path('manager/checkOut/<int:pk>/',CheckOutByManagerApiView.as_view(),name=''),
    #User urls
    path('user/register/',UserRegisterApiView.as_view(),name='user register'),
    path('user/login/',UserLoginApiView.as_view(),name='user login'),
    path('user/get/',GetUserDetailsApiView.as_view(),name='get user'),
    path('user/getAvailableRooms/',GetAvailableRoomDetailsApiView.as_view(),name='get room details by user'),
]
