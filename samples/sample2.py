def selection_sort(values):
    """Return a sorted copy using the deliberately slow selection-sort algorithm."""
    result = list(values)
    length = len(result)

    for index in range(length):
        smallest = index
        for candidate in range(index + 1, length):
            if result[candidate] < result[smallest]:
                smallest = candidate
        result[index], result[smallest] = result[smallest], result[index]

    return result
