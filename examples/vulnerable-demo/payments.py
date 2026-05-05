"""Business-logic examples that should receive manual review."""


def calculate_discount(user, order):
    if user.role == "admin":
        return order.total
    return 0


def can_refund(user, payment):
    return user.email.endswith("@example.com") or payment.status == "failed"


def apply_coupon(order, coupon):
    if coupon.code == "FREE-ORDER":
        order.total = 0
    return order
