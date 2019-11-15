list_a = [1, 2, 3]
b = list_a
b = [4, 5, 6]
list_a[:0] = b
print(list_a)