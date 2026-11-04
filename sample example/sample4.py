class Inventory:
    """Track item quantities and prices in a small inventory."""

    def __init__(self):
        """Initialize an empty inventory."""
        self._items = {}

    def add(self, name, quantity, unit_price):
        """Add or replace an inventory item."""
        if quantity < 0 or unit_price < 0:
            raise ValueError("Quantity and price must be non-negative")
        self._items[name] = {"quantity": quantity, "unit_price": unit_price}

    def total_value(self):
        """Return the combined value of all inventory items."""
        return sum(
            item["quantity"] * item["unit_price"]
            for item in self._items.values()
        )

    def low_stock(self, limit=5):
        """Return names of items whose quantity is below the limit."""
        return [
            name for name, item in self._items.items()
            if item["quantity"] < limit
        ]
