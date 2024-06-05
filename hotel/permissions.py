from rest_framework.permissions import BasePermission


class IsAdminOrNot(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return request.user.role=='A'
    
class IsManagerOrNot(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role=='M'

class IsUserOrNot(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role=='U'
