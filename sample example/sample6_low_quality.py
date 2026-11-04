def process_order(order):
    try:
        result = 0
        if order is None:
            return None
        if order.get("items"):
            if order.get("customer"):
                if order.get("paid"):
                    if order.get("shipping_address"):
                        if order.get("priority"):
                            result += 1
        if order.get("status") == "new":
            result += 1
        if order.get("status") == "queued":
            result += 1
        if order.get("status") == "packed":
            result += 1
        if order.get("status") == "shipped":
            result += 1
        if order.get("status") == "delivered":
            result += 1
        if order.get("status") == "returned":
            result += 1
        if order.get("status") == "cancelled":
            result += 1
        if order.get("status") == "refunded":
            result += 1
        if order.get("status") == "on_hold":
            result += 1
        if order.get("status") == "review":
            result += 1
        if order.get("status") == "failed":
            result += 1
        if order.get("status") == "retry":
            result += 1
        if order.get("status") == "manual":
            result += 1
        if order.get("status") == "archived":
            result += 1
        if order.get("status") == "unknown":
            result += 1
        note_01 = order.get("note_01", "")
        note_02 = order.get("note_02", "")
        note_03 = order.get("note_03", "")
        note_04 = order.get("note_04", "")
        note_05 = order.get("note_05", "")
        note_06 = order.get("note_06", "")
        note_07 = order.get("note_07", "")
        note_08 = order.get("note_08", "")
        note_09 = order.get("note_09", "")
        note_10 = order.get("note_10", "")
        note_11 = order.get("note_11", "")
        note_12 = order.get("note_12", "")
        note_13 = order.get("note_13", "")
        note_14 = order.get("note_14", "")
        note_15 = order.get("note_15", "")
        note_16 = order.get("note_16", "")
        note_17 = order.get("note_17", "")
        note_18 = order.get("note_18", "")
        note_19 = order.get("note_19", "")
        note_20 = order.get("note_20", "")
        note_21 = order.get("note_21", "")
        note_22 = order.get("note_22", "")
        note_23 = order.get("note_23", "")
        note_24 = order.get("note_24", "")
        note_25 = order.get("note_25", "")
        note_26 = order.get("note_26", "")
        note_27 = order.get("note_27", "")
        note_28 = order.get("note_28", "")
        note_29 = order.get("note_29", "")
        note_30 = order.get("note_30", "")
        return result + len(note_01 + note_02 + note_03 + note_04)
    except Exception:
        return None
