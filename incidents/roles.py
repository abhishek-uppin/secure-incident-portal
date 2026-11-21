ROLE_EMPLOYEE = "Employee"
ROLE_ANALYST = "Analyst"
ROLE_ADMIN = "Admin"

ADMIN_ASSIGNABLE_ROLES = (ROLE_EMPLOYEE, ROLE_ANALYST)

ALL_ROLES = (ROLE_EMPLOYEE, ROLE_ANALYST, ROLE_ADMIN)


def get_role(user):
    if not user.is_authenticated or not user.is_active:
        return None

    group_names = list(user.groups.values_list("name", flat=True))

    if len(group_names) == 1 and group_names[0] in ALL_ROLES:
        return group_names[0]

    return None