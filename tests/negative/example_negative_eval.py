import html
user_input = input("Enter something: ")
safe_input = html.escape(user_input)
print(safe_input)