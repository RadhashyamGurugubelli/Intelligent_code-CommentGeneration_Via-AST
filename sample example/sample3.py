def calculate_total(prices, tax_rate):
    """Return the total price after applying a tax rate."""
    subtotal = sum(prices)
    tax = subtotal * tax_rate
    return round(subtotal + tax, 2)
